use std::process::Command;
use std::str;

use aws_sdk_ecr as ecr;
use aws_sdk_ecs::types::TaskDefinition;
use aws_sdk_ecs::Client as ECSClient;
use aws_types::region::Region;
use colored::*;
use regex::Regex;
use tokio::runtime::Runtime;

fn execute_command(command: &str, show_command: bool, alt_command: Option<String>) -> String {
    if show_command {
        println!(
            "{}",
            format!("Executing command: {}", command).blue().bold()
        );
    } else if alt_command.is_some() {
        println!(
            "{}",
            format!("Executing command: {}", alt_command.unwrap())
                .blue()
                .bold()
        );
    }
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        println!("{}", "Command executed successfully.".green().bold());
        str::from_utf8(&output.stdout).unwrap().trim().to_string()
    } else {
        println!(
            "{}",
            format!("Error executing command: {}", command).red().bold()
        );
        println!("{}", str::from_utf8(&output.stderr).unwrap());
        panic!("{}", str::from_utf8(&output.stderr).unwrap());
    }
}

fn get_latest_tag(tags: &Vec<&str>, app_name: &str) -> (i32, i32, i32) {
    println!("{}", "Determining the latest tag...".cyan().bold());
    let pattern = Regex::new(&format!(r"{}-(\d+)\.(\d+)\.(\d+)", app_name)).unwrap();
    let mut latest_version = (0, 0, 0);
    for tag in tags {
        if let Some(captures) = pattern.captures(tag) {
            let major = captures[1].parse::<i32>().unwrap();
            let minor = captures[2].parse::<i32>().unwrap();
            let patch = captures[3].parse::<i32>().unwrap();
            if (major, minor, patch) > latest_version {
                latest_version = (major, minor, patch);
            }
        }
    }
    println!(
        "{}",
        format!(
            "Latest version found: {}.{}.{}",
            latest_version.0, latest_version.1, latest_version.2
        )
        .cyan()
        .bold()
    );
    latest_version
}

fn increment_version(version: (i32, i32, i32)) -> (i32, i32, i32) {
    let (major, minor, patch) = version;
    let new_version = (major, minor, patch + 1);
    println!(
        "{}",
        format!(
            "Incremented version to: {}.{}.{}",
            new_version.0, new_version.1, new_version.2
        )
        .cyan()
        .bold()
    );
    new_version
}

async fn get_ecr_login_password(client: &ecr::Client) -> String {
    println!("{}", "Getting ECR login password...".yellow().bold());
    let request = client.get_authorization_token().send().await.unwrap();
    let auth_data = request.authorization_data.unwrap();
    let token = &auth_data[0].authorization_token.as_ref().unwrap();
    let decoded = base64::decode(token).unwrap();
    let login_password = str::from_utf8(&decoded)
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .to_string();
    println!("{}", "ECR login password retrieved.".yellow().bold());
    login_password
}

async fn get_latest_ecr_image_tags(
    client: &ecr::Client,
    repository_name: &str,
) -> Option<Vec<String>> {
    println!("{}", "Fetching latest ECR image tags...".yellow().bold());
    let mut pages = client
        .list_images()
        .repository_name(repository_name)
        .into_paginator()
        .send();
    let mut tags = Vec::new();

    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(page) => page,
            Err(err) => {
                eprintln!("Error fetching page: {:?}", err);
                return None;
            }
        };

        if let Some(image_ids) = page.image_ids {
            for image_id in image_ids {
                if let Some(tag) = image_id.image_tag {
                    tags.push(tag);
                }
            }
        }
    }

    if tags.is_empty() {
        println!("{}", "No tags found.".red().bold());
        None
    } else {
        println!("{}", format!("Tags found: {:#?}", tags).yellow().bold());
        Some(tags)
    }
}

async fn get_latest_task_definition(
    client: &ECSClient,
    task_family: &String,
) -> Option<TaskDefinition> {
    println!(
        "{}",
        "Fetching latest ECS task definition...".yellow().bold()
    );
    let task_definition = client
        .describe_task_definition()
        .task_definition(task_family)
        .send()
        .await;

    match task_definition {
        Ok(response) => response.task_definition,
        Err(err) => {
            eprintln!("Error fetching task definition: {:?}", err);
            None
        }
    }
}

async fn register_new_task_definition(
    client: &ECSClient,
    task_def: TaskDefinition,
    new_image: &str,
) -> String {
    let mut container_definitions = task_def.container_definitions.clone().unwrap();

    for container_def in &mut container_definitions {
        container_def.image = Some(new_image.to_string());
    }

    let new_task_definition = client
        .register_task_definition()
        .set_family(task_def.family)
        .set_task_role_arn(task_def.task_role_arn)
        .set_execution_role_arn(task_def.execution_role_arn)
        .set_network_mode(task_def.network_mode)
        .set_container_definitions(Some(container_definitions))
        .set_volumes(task_def.volumes)
        .set_placement_constraints(task_def.placement_constraints)
        .set_requires_compatibilities(task_def.requires_compatibilities)
        .set_cpu(task_def.cpu)
        .set_memory(task_def.memory)
        .send()
        .await
        .expect("Error registering new task definition");

    new_task_definition
        .task_definition
        .expect("No task definition registered")
        .task_definition_arn
        .unwrap()
}

async fn update_ecs_service(
    client: &ECSClient,
    cluster: &str,
    service: &str,
    task_definition_arn: &str,
) {
    println!("{}", "Updating ECS service...".yellow().bold());
    let _ = client
        .update_service()
        .cluster(cluster)
        .service(service)
        .task_definition(task_definition_arn)
        .send()
        .await
        .expect("Error updating ECS service");
    println!("{}", "ECS service updated.".yellow().bold());
}

fn main() {
    dotenvy::dotenv().ok();
    let region = std::env::var("REGION").expect("REGION must be set");
    let repository = std::env::var("REPOSITORY").expect("REPOSITORY must be set");
    let repository_url = std::env::var("REPOSITORY_URL").expect("REPOSITORY_URL must be set");
    let app_name = std::env::var("APP_NAME").expect("APP_NAME must be set");
    let cluster_name = std::env::var("CLUSTER_NAME").expect("CLUSTER_NAME must be set");
    let service_name = std::env::var("SERVICE_NAME").expect("SERVICE_NAME must be set");
    let task_family = std::env::var("TASK_FAMILY").expect("TASK_FAMILY must be set");

    println!("{}", "Starting ECR to ECS process...".magenta().bold());
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let region = Region::new(region);
        let config = aws_config::from_env().region(region.clone()).load().await;
        let ecr_client = ecr::Client::new(&config);
        let ecs_client = ECSClient::new(&config);

        // Get AWS ECR login password
        let login_password = get_ecr_login_password(&ecr_client).await;
        let login_command = format!(
            "echo {} | docker login --username AWS --password-stdin {}",
            login_password, repository_url
        );
        execute_command(
            &login_command,
            false,
            Some(String::from(
                "echo (pw) | docker login --username AWS --password-stdin (url)",
            )),
        );

        // Get the latest image tags from ECR
        let latest_tag: (i32, i32, i32) =
            match get_latest_ecr_image_tags(&ecr_client, &repository).await {
                Some(tags) => get_latest_tag(
                    &tags.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    &app_name,
                ),
                None => (0, 0, 0),
            };

        let new_version = increment_version(latest_tag);
        let new_tag = format!(
            "{}-{}.{}.{}",
            app_name, new_version.0, new_version.1, new_version.2
        );
        let new_image = format!("{}:{}", repository_url, new_tag);

        // Build the new Docker image (assuming Dockerfile is present in the current directory)
        let build_command = format!("docker buildx build -t {} .", new_image);
        execute_command(&build_command, true, None);

        // Push the new Docker image to the ECR repository
        let push_command = format!("docker push {}", new_image);
        execute_command(&push_command, true, None);

        println!(
            "{}",
            format!("Successfully tagged and pushed {}", new_image)
                .green()
                .bold()
        );

        // Fetch latest task definition
        let latest_task_definition = get_latest_task_definition(&ecs_client, &task_family)
            .await
            .expect("Failed to get latest task definition");

        // Register new task definition with the new image
        let new_task_definition_arn =
            register_new_task_definition(&ecs_client, latest_task_definition, &new_image).await;

        // Update ECS service to use the new task definition
        update_ecs_service(
            &ecs_client,
            &cluster_name,
            &service_name,
            &new_task_definition_arn,
        )
        .await;
    });
    println!("{}", "ECR to ECS process completed.".magenta().bold());
}
