use std::fs::File;
use std::path::Path;
use starnav::*;
use starnav::{
    ObjectContainer,
    PointOfInterest,
};

fn main() {
    let mut nav_system = InterstellarNavigationSystem::new();

    let start = "New Babbage";
    let end = "Daymar";
    
    // pois.json, objContainers.json
    let pois_path = Path::new("pois.json");
    let obj_containers_path = Path::new("objContainers.json");

    let pois_file = File::open(pois_path).unwrap();
    let obj_containers_file = File::open(obj_containers_path).unwrap();

    let pois: Vec<PointOfInterest> = serde_json::from_reader(pois_file).unwrap();
    let obj_containers: Vec<ObjectContainer> = serde_json::from_reader(obj_containers_file).unwrap();

    nav_system.load_containers(obj_containers);
    nav_system.load_pois(pois);

    nav_system.update_time(1.0);
    
    // Important: Update positions to ensure all POIs have proper global coordinates
    nav_system.update_positions();

    let start_id = nav_system.pois.iter().find(|poi| poi.1.name == start).unwrap().0;
    let end_id = nav_system.containers.iter().find(|poi| poi.1.name == end).unwrap().0;

    println!("start_id: {}", start_id);
    println!("end_id: {}", end_id);

    let constraints =
        NavigationConstraints {
            min_approach_distance: 10_000.0, // Minimum distance to approach objects
            prefer_distance: true,           // Prioritize shortest distance
            prefer_segments: false,          // Don't prioritize fewer segments
            prefer_safety: false,            // Don't prioritize safety over distance
            buffer_distance: 10_000.0,       // Buffer around obstacles
            max_hydrogen_distance: 100_000.0, // Max distance for hydrogen propulsion
            avoid_atmospheres: true,         // Avoid atmospheric entry
            min_altitude: 5_000.0,           // Minimum altitude above surfaces
            safety_margin: 20_000.0,         // Extra safety margin
        };

    let path =
        nav_system.calculate_path(
            *start_id,
            EntityType::PointOfInterest,
            *end_id,
            EntityType::ObjectContainer,
            Some(constraints),
        );

    println!(
        "{}",
        serde_json::to_string_pretty(&path).unwrap(),
    );
}
