use std::sync::Arc;
use rand::seq::IndexedRandom;
use starnav::vector3::Vector3;
use starnav::StaticAstronomicalData;
use starnav::{
    create_navigation_system,
    types::{ContainerType, Entity, LineOfSightResult, NavigationPlan, PathSegment, PoiType, PointOfInterest, Quaternion, System, TravelType},
};
use log::{info, warn, error};
use std::time::{Instant};
use rand::{thread_rng, Rng, seq::SliceRandom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    print_header("STARNAV BRUTE FORCE NAVIGATION VERIFICATION TEST");

    // Include the JSON files at compile time
    let poi_data = include_bytes!("../pois.json");
    let container_data = include_bytes!("../objContainers.json");

    let (pois, containers) =
        starnav::data_loader::load_navigation_data_from_bytes(
            poi_data,
            container_data,
        ).unwrap();

    // Create navigation system
    let mut nav_system = create_navigation_system(pois.clone(), containers);

    // Get all POI names for random selection
    let poi_names: Vec<String> = pois.iter()
        .filter(|poi| poi.system == System::Stanton)
        .map(|poi| poi.name.clone())
        .collect();

    print_info(&format!("Total POIs available: {}", poi_names.len()));

    // Initialize random number generator
    let mut rng = thread_rng();
    
    // Number of random routes to try
    let num_routes = 1000;
    let mut successful_routes = 0;
    let start_time = Instant::now();

    // Track failed route statistics
    let mut failed_routes_stats = FailedRoutesStatistics::new();

    for i in 0..num_routes {
        // Select random start and destination POIs
        let start = poi_names.choose(&mut rng).unwrap();
        let mut destination = poi_names.choose(&mut rng).unwrap();
        
        // Make sure start and destination are different
        while destination == start {
            destination = poi_names.choose(&mut rng).unwrap();
        }
        
        print_section(&format!("ROUTE TEST #{}: {} → {}", i + 1, start, destination));
        
        // Set position at start location
        nav_system.set_position_at_poi(start);
        
        // Get current position
        let current_position = nav_system.get_current_position();
        print_info(&format!("Starting position at {}: {:?}", start, current_position));
        
        // Plan navigation to destination
        print_info(&format!("Planning navigation to {}...", destination));
        
        match nav_system.plan_navigation(destination) {
            Some(plan) => {
                print_success(&format!("Navigation plan generated with {} segments", plan.segments.len()));
                
                // Verify the plan with brute force calculations
                if verify_navigation_plan(&nav_system, &plan) {
                    // Print detailed navigation instructions
                    print_detailed_navigation_plan(&plan);
                    successful_routes += 1;
                } else {
                    print_error("Route verification failed.");
                    // Collect statistics about the failed route
                    failed_routes_stats.record_failure(&nav_system, start, destination, &plan);
                }
            }
            None => {
                print_error(&format!("Could not generate a navigation plan to {}.", destination));
                // Collect statistics about the failed route
                failed_routes_stats.record_failed_plan(&nav_system, start, destination);
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    print_section("TEST SUMMARY");
    print_info(&format!("Tested {} random routes", num_routes));
    print_info(&format!("Successfully verified {} routes", successful_routes));
    print_info(&format!("Failed {} routes", num_routes - successful_routes));
    print_info(&format!("Test completed in {:.2} seconds", elapsed.as_secs_f64()));

    // Print failed routes statistics
    failed_routes_stats.print_summary();
    
    Ok(())
}

/// Verifies a navigation plan by checking line of sight between segments
fn verify_navigation_plan(nav_system: &starnav::SpaceNavigationSystem<StaticAstronomicalData>, plan: &NavigationPlan) -> bool {
    print_section("NAVIGATION PLAN VERIFICATION");
    print_info(&format!("Total distance: {:.2} km", plan.total_distance / 1000.0));
    print_info(&format!("Estimated travel time: {:.2} minutes", plan.total_estimated_time / 60.0));
    print_info(&format!("Quantum jumps: {}", plan.quantum_jumps));
    print_info(&format!("Path complexity: {:?}", plan.path_complexity));
    
    let mut current_position = plan.segments[0].from.position;
    let mut verification_passed = true;
    
    for (i, segment) in plan.segments.iter().enumerate() {
        print_subsection(&format!("SEGMENT {}: {} → {}", i + 1, segment.from.name, segment.to.name));
        print_info(&format!("Travel type: {:?}", segment.travel_type));
        print_info(&format!("Distance: {:.2} km", segment.distance / 1000.0));
        print_info(&format!("Estimated time: {:.2} seconds", segment.estimated_time));
        
        // Check if there's line of sight between the points
        let los_result = check_line_of_sight(nav_system, current_position, segment.to.position);
        
        if !los_result.has_los {
            if let Some(obstruction) = los_result.obstruction {
                print_error(&format!("Line of sight obstructed by: {}", obstruction.name));
                
                // Check if this matches the plan's expectation
                if segment.obstruction.is_none() {
                    print_error("Navigation plan did not account for this obstruction!");
                    verification_passed = false;
                } else if segment.obstruction.as_ref().unwrap() != &obstruction.name {
                    print_error(&format!("Navigation plan expected obstruction by {} but found {}",
                        segment.obstruction.as_ref().unwrap(), obstruction.name));
                    verification_passed = false;
                }
                
                print_success("Obstruction was correctly identified in the navigation plan");
            }
        } else if segment.obstruction.is_some() {
            print_error(&format!("Navigation plan expected obstruction by {} but found none",
                segment.obstruction.as_ref().unwrap()));
            verification_passed = false;
        }
        
        // Update current position for next segment
        current_position = segment.to.position;
    }
    
    if verification_passed {
        print_success("Navigation plan verification completed successfully!");
    } else {
        print_error("Navigation plan verification failed!");
    }
    
    verification_passed
}

/// Checks if there's a line of sight between two points
fn check_line_of_sight(
    nav_system: &starnav::SpaceNavigationSystem<StaticAstronomicalData>, 
    from: Vector3, 
    to: Vector3
) -> LineOfSightResult {
    // Get direction vector
    let direction = (to - from).normalized();
    let distance = to.distance(&from);
    
    // Check each container for intersection
    for container in nav_system.planner.data_provider.containers.iter() {
        // Skip containers that are too far away to be relevant
        let container_pos = container.position;
        let container_to_line = closest_point_on_line(from, to, container_pos);
        let distance_to_line = container_pos.distance(&container_to_line);
        
        // If the container is closer to the line than its radius, it might intersect
        if distance_to_line < container.body_radius {
            // Check if the closest point is actually on the segment
            let t = ((container_to_line - from).dot(&direction)) / distance;
            
            if t >= 0.0 && t <= 1.0 {
                // The container intersects the line segment
                return LineOfSightResult {
                    has_los: false,
                    obstruction: Some(Arc::new(container.clone())),
                };
            }
        }
    }
    
    // No obstructions found
    LineOfSightResult {
        has_los: true,
        obstruction: None,
    }
}

/// Finds the closest point on a line segment to a given point
fn closest_point_on_line(line_start: Vector3, line_end: Vector3, point: Vector3) -> Vector3 {
    let line_vec = line_end - line_start;
    let point_vec = point - line_start;
    
    let line_length = line_vec.distance(&Vector3::zero());
    let line_unit_vec = line_vec / line_length;
    
    let projection = point_vec.dot(&line_unit_vec);
    
    if projection <= 0.0 {
        return line_start;
    }
    
    if projection >= line_length {
        return line_end;
    }
    
    line_start + (line_unit_vec * projection)
}

/// Prints detailed information about a navigation plan
fn print_detailed_navigation_plan(plan: &NavigationPlan) {
    print_section("DETAILED NAVIGATION PLAN");
    print_info(&format!("Total distance: {:.2} km", plan.total_distance / 1000.0));
    print_info(&format!("Estimated travel time: {:.2} minutes", plan.total_estimated_time / 60.0));
    print_info(&format!("Quantum jumps: {}", plan.quantum_jumps));
    print_info(&format!("Path complexity: {:?}", plan.path_complexity));
    
    if let Some(container) = &plan.origin_container {
        print_info(&format!("Origin container: {} ({:?})", container.name, container.container_type));
    }
    
    print_subsection("NAVIGATION SEGMENTS");
    
    for (i, segment) in plan.segments.iter().enumerate() {
        print_box(&format!("SEGMENT {}: {} → {}", i + 1, segment.from.name, segment.to.name));
        print_detail(&format!("From position: {:?}", segment.from.position));
        print_detail(&format!("To position: {:?}", segment.to.position));
        print_detail(&format!("Distance: {:.2} km", segment.distance / 1000.0));
        print_detail(&format!("Travel type: {:?}", segment.travel_type));
        print_detail(&format!("Estimated time: {:.2} seconds", segment.estimated_time));
        print_detail(&format!("Direction: Pitch={:.2}°, Yaw={:.2}°, Roll={:.2}°", 
            segment.direction.pitch, segment.direction.yaw, segment.direction.roll));
        
        if let Some(obstruction) = &segment.obstruction {
            print_detail(&format!("Obstruction: {}", obstruction));
            print_detail(&format!("Is obstruction bypass: {}", segment.is_obstruction_bypass));
        }
    }
    
    if !plan.obstructions.is_empty() {
        print_subsection("DETECTED OBSTRUCTIONS");
        for (i, obstruction) in plan.obstructions.iter().enumerate() {
            print_detail(&format!("{}. {}", i + 1, obstruction));
        }
    }
}

// ASCII TUI helper functions
fn print_header(text: &str) {
    let width = text.len() + 8;
    let border = "═".repeat(width);
    println!("\n╔{}╗", border);
    println!("║    {}    ║", text);
    println!("╚{}╝\n", border);
}

fn print_section(text: &str) {
    let width = text.len() + 4;
    let border = "─".repeat(width);
    println!("\n┌{}┐", border);
    println!("│  {}  │", text);
    println!("└{}┘\n", border);
}

fn print_subsection(text: &str) {
    println!("\n┌─ {} ─┐", text);
    println!("│");
}

fn print_box(text: &str) {
    let width = text.len() + 2;
    let border = "─".repeat(width);
    println!("\n┌{}┐", border);
    println!("│ {} │", text);
    println!("└{}┘", border);
}

fn print_info(text: &str) {
    println!("│ ℹ️  {}", text);
}

fn print_success(text: &str) {
    println!("│ ✅ {}", text);
}

fn print_error(text: &str) {
    println!("│ ❌ {}", text);
}

fn print_detail(text: &str) {
    println!("│  • {}", text);
}

/// Structure to track statistics about failed routes
struct FailedRoutesStatistics {
    by_system: std::collections::HashMap<System, usize>,
    by_container_type: std::collections::HashMap<ContainerType, usize>,
    by_celestial_body: std::collections::HashMap<String, usize>,
    in_space_count: usize,
    by_closest_om: std::collections::HashMap<String, usize>,
    total_failures: usize,
    by_failure_reason: std::collections::HashMap<String, usize>,
    failed_routes: Vec<(String, String, String)>,
}

impl FailedRoutesStatistics {
    fn new() -> Self {
        FailedRoutesStatistics {
            by_system: std::collections::HashMap::new(),
            by_container_type: std::collections::HashMap::new(),
            by_celestial_body: std::collections::HashMap::new(),
            in_space_count: 0,
            by_closest_om: std::collections::HashMap::new(),
            total_failures: 0,
            by_failure_reason: std::collections::HashMap::new(),
            failed_routes: Vec::new(),
        }
    }

    fn record_failure(&mut self, nav_system: &starnav::SpaceNavigationSystem<StaticAstronomicalData>, 
                     start: &str, destination: &str, plan: &NavigationPlan) {
        self.total_failures += 1;
        
        // Get information about the current position
        if let Some(current_container) = nav_system.get_current_object_container() {
            // Increment count for system
            *self.by_system.entry(current_container.system).or_insert(0) += 1;
            
            // Increment count for container type
            *self.by_container_type.entry(current_container.container_type).or_insert(0) += 1;
            
            // Track celestial body information
            // if let Some(parent_body) = &current_container.parent_body {
            //     *self.by_celestial_body.entry(parent_body.clone()).or_insert(0) += 1;
            // }
            
            // Check if in space
            if current_container.container_type == ContainerType::JumpPoint
                || current_container.container_type == ContainerType::Lagrange
                || current_container.container_type == ContainerType::NavalStation
                || current_container.container_type == ContainerType::RefineryStation
                || current_container.container_type == ContainerType::RestStop
                || current_container.container_type == ContainerType::Star
            {
                self.in_space_count += 1;
            }
            
            // Track closest OM (Orbital Marker) if available
            // if let Some(closest_om) = nav_system.find_closest_om() {
            //     *self.by_closest_om.entry(closest_om.name.clone()).or_insert(0) += 1;
            // }
        }
        
        // Determine failure reason by checking the plan
        let reason = self.determine_failure_reason(nav_system, plan);
        
        // Record the failure reason
        *self.by_failure_reason.entry(reason.clone()).or_insert(0) += 1;
        
        // Record the failed route
        self.failed_routes.push((start.to_string(), destination.to_string(), reason));
    }
    
    fn determine_failure_reason(&self, nav_system: &starnav::SpaceNavigationSystem<StaticAstronomicalData>, 
                               plan: &NavigationPlan) -> String {
        let mut current_position = plan.segments[0].from.position;
        
        for (i, segment) in plan.segments.iter().enumerate() {
            // Check if there's line of sight between the points
            let los_result = check_line_of_sight(nav_system, current_position, segment.to.position);
            
            if !los_result.has_los {
                if let Some(obstruction) = los_result.obstruction {
                    // Check if this matches the plan's expectation
                    if segment.obstruction.is_none() {
                        return format!("Missing obstruction in segment {}: {}", i + 1, obstruction.name);
                    } else if segment.obstruction.as_ref().unwrap() != &obstruction.name {
                        return format!("Wrong obstruction in segment {}: expected {}, found {}", 
                            i + 1, segment.obstruction.as_ref().unwrap(), obstruction.name);
                    }
                }
            } else if segment.obstruction.is_some() {
                return format!("False obstruction in segment {}: expected {} but found none",
                    i + 1, segment.obstruction.as_ref().unwrap());
            }
            
            // Update current position for next segment
            current_position = segment.to.position;
        }
        
        // If we can't determine the specific reason
        "Unknown verification failure".to_string()
    }
    
    fn record_failed_plan(&mut self, nav_system: &starnav::SpaceNavigationSystem<StaticAstronomicalData>, 
                         start: &str, destination: &str) {
        // Same as record_failure but for cases where no plan could be generated
        self.total_failures += 1;
        
        if let Some(current_container) = nav_system.get_current_object_container() {
            *self.by_system.entry(current_container.system).or_insert(0) += 1;
            *self.by_container_type.entry(current_container.container_type).or_insert(0) += 1;
            
            // if let Some(parent_body) = &current_container.parent_body {
            //     *self.by_celestial_body.entry(parent_body.clone()).or_insert(0) += 1;
            // }
            
            if current_container.container_type == ContainerType::JumpPoint
                || current_container.container_type == ContainerType::Lagrange
                || current_container.container_type == ContainerType::NavalStation
                || current_container.container_type == ContainerType::RefineryStation
                || current_container.container_type == ContainerType::RestStop
                || current_container.container_type == ContainerType::Star
            {
                self.in_space_count += 1;
            }
            
            // if let Some(closest_om) = nav_system.find_closest_om() {
            //     *self.by_closest_om.entry(closest_om.name.clone()).or_insert(0) += 1;
            // }
        }
        
        // Record the reason as "No plan generated"
        *self.by_failure_reason.entry("No navigation plan generated".to_string()).or_insert(0) += 1;
        
        // Record the failed route
        self.failed_routes.push((start.to_string(), destination.to_string(), "No navigation plan generated".to_string()));
    }
    
    fn print_summary(&self) {
        if self.total_failures == 0 {
            return;
        }
        
        print_section("FAILED ROUTES STATISTICS");
        
        // Print by failure reason first (most important)
        print_subsection("By Failure Reason");
        for (reason, count) in &self.by_failure_reason {
            let percentage = ((*count as f64) / (self.total_failures as f64) * 100.0).round();
            print_detail(&format!("{}: {} ({}%)", reason, count, percentage));
        }
        
        // Print by system
        print_subsection("By System");
        for (system, count) in &self.by_system {
            let percentage = ((*count as f64) / (self.total_failures as f64) * 100.0).round();
            print_detail(&format!("{:?}: {} ({}%)", system, count, percentage));
        }
        
        // Print by container type
        print_subsection("By Container Type");
        for (container_type, count) in &self.by_container_type {
            let percentage = ((*count as f64) / (self.total_failures as f64) * 100.0).round();
            print_detail(&format!("{:?}: {} ({}%)", container_type, count, percentage));
        }
        
        // Print by celestial body
        print_subsection("By Celestial Body (Planet/Moon)");
        for (body, count) in &self.by_celestial_body {
            let percentage = ((*count as f64) / (self.total_failures as f64) * 100.0).round();
            print_detail(&format!("{}: {} ({}%)", body, count, percentage));
        }
        
        // Print in space count
        print_subsection("In Space");
        let in_space_percentage = ((self.in_space_count as f64) / (self.total_failures as f64) * 100.0).round();
        print_detail(&format!("Failures in open space: {} ({}%)", self.in_space_count, in_space_percentage));
        
        // Print by closest OM
        print_subsection("By Closest Orbital Marker");
        for (om, count) in &self.by_closest_om {
            let percentage = ((*count as f64) / (self.total_failures as f64) * 100.0).round();
            print_detail(&format!("{}: {} ({}%)", om, count, percentage));
        }
        
        // Display a sample of failed routes with reasons
        print_subsection("Sample Failed Routes (up to 10)");
        let sample_count = std::cmp::min(10, self.failed_routes.len());
        for i in 0..sample_count {
            let (start, dest, reason) = &self.failed_routes[i];
            print_detail(&format!("{} → {}: {}", start, dest, reason));
        }
    }
}
