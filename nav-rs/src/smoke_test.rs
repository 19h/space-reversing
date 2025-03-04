use starnav::{create_navigation_system, types::{PointOfInterest, ContainerType, PoiType, System, Quaternion}};
use starnav::vector3::Vector3;

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
    let mut nav_system = create_navigation_system(pois, containers);
    
    // Set current position at Lorville on Hurston
    println!("Setting position at Lorville on Hurston");
    nav_system.set_position_local("Hurston", -328.91, -785.98, 564.17);
    
    // Plan navigation to Shubin Mining Facility
    println!("Planning navigation to Shubin Mining Facility SCD-1...");
    match nav_system.plan_navigation("Shubin Mining Facility SCD-1") {
        Some(plan) => {
            // Print navigation instructions
            let instructions = nav_system.format_navigation_instructions(&plan);
            println!("\nNavigation Plan:");
            println!("{}", instructions);
            
            // Find nearby POIs at destination
            println!("\nNearby points of interest at destination:");
            let nearby = nav_system.find_nearby_pois(3);
            for (i, poi) in nearby.iter().enumerate() {
                println!("{}. {} - {:.2} km", i + 1, poi.name, poi.distance);
            }
        },
        None => println!("Error: Could not generate a navigation plan"),
    }
    
    Ok(())
}
