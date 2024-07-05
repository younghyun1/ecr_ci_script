use std::process::Command;
use std::str;

use aws_sdk_ecr as ecr;
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

fn main() {
    dotenvy::dotenv().ok();
    let region = std::env::var("REGION").expect("REGION must be set");
    let repository = std::env::var("REPOSITORY").expect("REPOSITORY must be set");
    let repository_url = std::env::var("REPOSITORY_URL").expect("REPOSITORY_URL must be set");
    let app_name = std::env::var("APP_NAME").expect("APP_NAME must be set");

    println!("{}", "Starting ECR image processing...".magenta().bold());
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let region = Region::new(region);
        let config = aws_config::from_env().region(region).load().await;
        let client = ecr::Client::new(&config);

        // Get AWS ECR login password
        let login_password = get_ecr_login_password(&client).await;
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
            match get_latest_ecr_image_tags(&client, &repository).await {
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

        // Build the new image (assuming Dockerfile is present in the current directory)
        let build_command = format!("docker buildx build -t {}:{} .", repository_url, new_tag);
        execute_command(&build_command, true, None);

        // Push the new tag to the repository
        let push_command = format!("docker push {}:{}", repository_url, new_tag);
        execute_command(&push_command, true, None);

        println!(
            "{}",
            format!(
                "Successfully tagged and pushed {}:{}",
                repository_url, new_tag
            )
            .green()
            .bold()
        );
    });
    println!("{}", "ECR image processing completed.".magenta().bold());
}
