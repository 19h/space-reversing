use std::fs::File;
use std::path::Path;
use starnav::*;
use starnav::{
    ObjectContainer,
    PointOfInterest,
};

fn main() {
    let mut nav_system = InterstellarNavigationSystem::new();
    
    // pois.json, objContainers.json
    let pois_path = Path::new("pois.json");
    let obj_containers_path = Path::new("objContainers.json");

    let pois_file = File::open(pois_path).unwrap();
    let obj_containers_file = File::open(obj_containers_path).unwrap();

    let pois: Vec<PointOfInterest> = serde_json::from_reader(pois_file).unwrap();
    let obj_containers: Vec<ObjectContainer> = serde_json::from_reader(obj_containers_file).unwrap();

    nav_system.load_containers(obj_containers);
    nav_system.load_pois(pois);
}