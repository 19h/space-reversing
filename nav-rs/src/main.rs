use starnav::data_loader;

use clap::{App, Arg, SubCommand};
use env_logger::Builder;
use log::LevelFilter;
use std::io::Write;

use starnav::create_navigation_system;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] {} - {}",
                record.level(),
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();

    // Parse command-line arguments
    let matches = App::new("Space Navigation System")
        .version("1.0")
        .author("Star Citizen Navigation Team")
        .about("Interplanetary navigation for space travelers")
        .arg(
            Arg::with_name("poi_file")
                .short("p")
                .long("pois")
                .value_name("FILE")
                .help("Points of interest JSON file")
                .required(true),
        )
        .arg(
            Arg::with_name("container_file")
                .short("c")
                .long("containers")
                .value_name("FILE")
                .help("Object containers JSON file")
                .required(true),
        )
        .subcommand(
            SubCommand::with_name("navigate")
                .about("Plan navigation to a destination")
                .arg(
                    Arg::with_name("from_container")
                        .short("f")
                        .long("from")
                        .value_name("CONTAINER")
                        .help("Starting container (planet/moon)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_x")
                        .long("x")
                        .value_name("X")
                        .help("Local X coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_y")
                        .long("y")
                        .value_name("Y")
                        .help("Local Y coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_z")
                        .long("z")
                        .value_name("Z")
                        .help("Local Z coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("destination")
                        .short("d")
                        .long("dest")
                        .value_name("DESTINATION")
                        .help("Destination name (POI or container)")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("nearby")
                .about("Find nearby points of interest")
                .arg(
                    Arg::with_name("from_container")
                        .short("f")
                        .long("from")
                        .value_name("CONTAINER")
                        .help("Starting container (planet/moon)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_x")
                        .long("x")
                        .value_name("X")
                        .help("Local X coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_y")
                        .long("y")
                        .value_name("Y")
                        .help("Local Y coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("local_z")
                        .long("z")
                        .value_name("Z")
                        .help("Local Z coordinate (km)")
                        .required(true),
                )
                .arg(
                    Arg::with_name("limit")
                        .short("l")
                        .long("limit")
                        .value_name("NUM")
                        .help("Maximum number of nearby POIs to find")
                        .default_value("5"),
                ),
        )
        .get_matches();

    // Load data
    let poi_file = matches.value_of("poi_file").unwrap();
    let container_file = matches.value_of("container_file").unwrap();

    println!("Loading navigation data...");
    let (pois, containers) = data_loader::load_navigation_data(poi_file, container_file)?;
    println!(
        "Loaded {} points of interest and {} object containers",
        pois.len(),
        containers.len()
    );

    // Create navigation system
    let mut starnav = create_navigation_system(pois, containers);

    // Execute requested command
    if let Some(matches) = matches.subcommand_matches("navigate") {
        // Extract navigation parameters
        let from_container = matches.value_of("from_container").unwrap();
        let local_x = matches.value_of("local_x").unwrap().parse::<f64>()?;
        let local_y = matches.value_of("local_y").unwrap().parse::<f64>()?;
        let local_z = matches.value_of("local_z").unwrap().parse::<f64>()?;
        let destination = matches.value_of("destination").unwrap();

        // Set position and plan route
        println!(
            "Setting position at {} ({}, {}, {})",
            from_container, local_x, local_y, local_z
        );
        starnav.set_position_local(from_container, local_x, local_y, local_z);

        println!("Planning route to {}...", destination);
        match starnav.plan_navigation(destination) {
            Some(plan) => {
                // Print navigation instructions
                let instructions = starnav.format_navigation_instructions(&plan);
                println!("\n{}", instructions);

                // Show nearby landmarks at destination
                if let Some(last_segment) = plan.segments.last() {
                    let destination_pos = &last_segment.to.position;
                    let nearby = starnav.find_nearby_pois(3);

                    let filtered_nearby: Vec<_> = nearby
                        .into_iter()
                        .filter(|poi| poi.distance < 100.0 && poi.name != destination)
                        .collect();

                    if !filtered_nearby.is_empty() {
                        println!("\nNearby landmarks at destination:");
                        for nd in filtered_nearby {
                            println!("- {} ({:.2} km)", nd.name, nd.distance);
                        }
                    }
                }
            }
            None => println!(
                "Error: Could not generate a navigation plan to {}",
                destination
            ),
        }
    } else if let Some(matches) = matches.subcommand_matches("nearby") {
        // Extract parameters
        let from_container = matches.value_of("from_container").unwrap();
        let local_x = matches.value_of("local_x").unwrap().parse::<f64>()?;
        let local_y = matches.value_of("local_y").unwrap().parse::<f64>()?;
        let local_z = matches.value_of("local_z").unwrap().parse::<f64>()?;
        let limit = matches.value_of("limit").unwrap().parse::<usize>()?;

        // Set position and find nearby POIs
        println!(
            "Setting position at {} ({}, {}, {})",
            from_container, local_x, local_y, local_z
        );
        starnav.set_position_local(from_container, local_x, local_y, local_z);

        println!("Finding nearby points of interest...");
        let nearby = starnav.find_nearby_pois(limit);

        if nearby.is_empty() {
            println!("No nearby points of interest found.");
        } else {
            println!("Nearby points of interest:");
            for (i, nd) in nearby.iter().enumerate() {
                println!("{}. {} - {:.2} km", i + 1, nd.name, nd.distance);
            }
        }
    } else {
        println!("No command specified. Use --help for usage information.");
    }

    Ok(())
}
