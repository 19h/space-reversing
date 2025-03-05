use starnav::vector3::Vector3;
use starnav::{
    create_navigation_system,
    types::{ContainerType, PoiType, PointOfInterest, Quaternion, System},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("Running smoke test for Space Navigation System");

    // Include the JSON files at compile time when the feature is enabled
    let poi_data = include_bytes!("../pois.json");
    let container_data = include_bytes!("../objContainers.json");

    let (pois, containers) =
        starnav::data_loader::load_navigation_data_from_bytes(
            poi_data,
            container_data,
        ).unwrap();

    // Create navigation system
    let mut nav_system =
        create_navigation_system(
            pois,
            containers,
        );

    // Set current position at Lorville on Hurston
    println!("Setting position at Lorville on Hurston");

    //nav_system.set_position_local(
    //    "Hurston",
    //    -328.91,
    //    -785.98,
    //    564.17,
    //);
    nav_system.set_position_at_poi("Lorville");

    // Plan navigation to Shubin Mining Facility
    println!("Planning navigation to Shubin Mining Facility SCD-1...");

    match nav_system.plan_navigation("Finn's Folly (Hydrona Farm)") {
        Some(plan) => {
            //println!("{}", serde_json::to_string_pretty(&plan).unwrap());

            // Print navigation instructions
            let instructions =
                nav_system.format_navigation_instructions(
                    &plan,
                );

            println!("\nNavigation Plan:");
            println!("{}", instructions);

            // Find nearby POIs at destination
            println!("\nNearby points of interest at destination:");

            let nearby = nav_system.find_nearby_pois(3);

            for (i, poi) in nearby.iter().enumerate() {
                println!("{}. {} - {:.2} km", i + 1, poi.name, poi.distance);
            }
        }
        None => println!("Error: Could not generate a navigation plan"),
    }

    // // Dump visibility graph to DOT format
    // println!("\nDumping visibility graph to visibility.dot");
    
    // let mut dot_file = std::fs::File::create("visibility.dot").expect("Failed to create DOT file");
    // use std::io::Write;
    
    // writeln!(dot_file, "digraph visibility {{").expect("Failed to write to DOT file");
    // writeln!(dot_file, "  node [shape=box];").expect("Failed to write to DOT file");
    
    // // Track edges we've already written to avoid duplicates
    // let mut written_edges = std::collections::HashSet::new();
    
    // for (_node_key, edges) in &nav_system.planner.visibility_graph {
    //     for edge in edges {
    //         let from_name = &edge.from_node.name;
    //         let to_name = &edge.to_node.name;
            
    //         // Create a unique identifier for this edge (both directions)
    //         let edge_id = if from_name < to_name {
    //             format!("{}_{}", from_name, to_name)
    //         } else {
    //             format!("{}_{}", to_name, from_name)
    //         };
            
    //         // Only write this edge if we haven't seen it before
    //         if written_edges.insert(edge_id) {
    //             let color = if edge.has_los { "green" } else { "red" };
    //             let label = format!("{:.2}km", edge.distance / 1000.0);
                
    //             writeln!(
    //                 dot_file,
    //                 "  \"{}\" -> \"{}\" [label=\"{}\", color={}];",
    //                 from_name, to_name, label, color
    //             ).expect("Failed to write to DOT file");
    //         }
    //     }
    // }
    
    // writeln!(dot_file, "}}").expect("Failed to write to DOT file");
    // println!("Visibility graph dumped successfully");
    
    Ok(())
}
