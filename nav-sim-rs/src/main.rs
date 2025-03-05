use rand::seq::{IndexedRandom};
use starnav::types::{ContainerType, EulerAngles, NavNodeType, PathPoint, PoiType, Quaternion, System, TravelType};
use starnav::{types::PathSegment, *};
use starnav::vector3::Vector3;
use std::{collections::HashMap, thread, time::{Duration, Instant}};
use rand::{Rng, rngs::ThreadRng};

fn main() {
    println!("Running Space Navigation Simulation System");

    // Include the JSON files at compile time when the feature is enabled
    let poi_data = include_bytes!("../pois.json");
    let container_data = include_bytes!("../objContainers.json");

    let (pois, containers) =
        starnav::data_loader::load_navigation_data_from_bytes(
            poi_data,
            container_data,
        ).unwrap();
    
    // Initialize simulation
    let mut simulation = SolarSystemSimulation::new(pois, containers);
    
    // Create actors
    simulation.create_random_actors(50);
    
    // Run simulation
    simulation.run(Duration::from_secs(3600), Duration::from_millis(100));
}

/// Vehicle types with their speeds in m/s
#[derive(Debug, Clone, Copy, PartialEq)]
enum Vehicle {
    OnFoot { speed: f64 },                    // Walking/running
    GroundVehicle { model: GroundVehicleType, speed: f64 }, // Ground vehicle
    Spacecraft { model: SpacecraftType, speed: f64, quantum_speed: f64 }, // Space vehicle
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GroundVehicleType {
    Cyclone,    // Fast buggy
    Ursa,       // Armored rover
    PTV,        // Golf cart
    Ranger,     // Motorcycle
    Nox,        // Hover bike
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SpacecraftType {
    Aurora,     // Small starter ship
    Avenger,    // Small multi-purpose
    Cutlass,    // Medium multi-purpose
    Freelancer, // Medium cargo
    Constellation, // Large multi-purpose
    Carrack,    // Exploration vessel
    Hammerhead, // Large combat ship
    Bengal,     // Capital ship
}

/// Actor states for state machine
#[derive(Debug, Clone)]
enum ActorState {
    Idle { duration: Duration, start_time: Instant },
    Planning { destination: ActorDestination },
    Traveling { 
        destination: ActorDestination,
        path: Vec<PathSegment>,
        current_segment_index: usize,
        progress: f64, // 0.0 to 1.0 along current segment
    },
    Exploring { 
        poi: String,
        duration: Duration,
        start_time: Instant 
    },
    Trading { 
        buy_location: String, 
        sell_location: String,
        cargo: String,
        quantity: f64,
        stage: TradingStage 
    },
    Mining { 
        location: String,
        resource: String,
        progress: f64,
        duration: Duration 
    },
    Socializing {
        location: String,
        other_actors: Vec<usize>,
        duration: Duration,
        start_time: Instant
    },
}

#[derive(Debug, Clone, PartialEq)]
enum TradingStage {
    TravelingToBuy,
    Buying,
    TravelingToSell,
    Selling,
}

#[derive(Debug, Clone, PartialEq)]
enum ActorDestination {
    PointOfInterest(String),
    ObjectContainer(String),
    SpecificLocation { 
        container: String, 
        position: Vector3 
    },
    OrbitalMarker { 
        container: String, 
        marker: String 
    },
}

/// Actor in the simulation
#[derive(Debug, Clone)]
struct Actor {
    id: usize,
    name: String,
    position: Vector3,
    rotation: Quaternion,
    current_system: System,
    current_container: Option<String>,
    vehicle: Vehicle,
    state: ActorState,
    wallet: f64,  // Currency for trading
    inventory: HashMap<String, f64>, // Resources/items and their quantities
    behavior_profile: BehaviorProfile,
}

/// Behavior weights to influence actor decisions
#[derive(Debug, Clone)]
struct BehaviorProfile {
    explorer_tendency: f64,  // 0.0-1.0: higher means more exploration
    trader_tendency: f64,    // 0.0-1.0: higher means more trading
    miner_tendency: f64,     // 0.0-1.0: higher means more mining
    combat_tendency: f64,    // 0.0-1.0: higher means more combat
    social_tendency: f64,    // 0.0-1.0: higher means more socializing
}

/// Overall simulation controller
struct SolarSystemSimulation {
    actors: Vec<Actor>,
    astronomical_data: StaticAstronomicalData,
    rng: ThreadRng,
    simulation_time: f64, // Current time in seconds
    real_start_time: Instant,
}

impl SolarSystemSimulation {
    fn new(pois: Vec<PointOfInterest>, containers: Vec<ObjectContainer>) -> Self {
        Self {
            actors: Vec::new(),
            astronomical_data: StaticAstronomicalData::new(pois, containers),
            rng: rand::rng(),
            simulation_time: 0.0,
            real_start_time: Instant::now(),
        }
    }
    
    fn create_random_actors(&mut self, count: usize) {
        // Names for random generation
        let first_names = ["Alex", "Taylor", "Jordan", "Morgan", "Riley", "Casey", "Avery", "Quinn"];
        let last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Wilson"];
        
        for id in 0..count {
            // Generate random name
            let first_name = first_names.choose(&mut self.rng).unwrap();
            let last_name = last_names.choose(&mut self.rng).unwrap();
            let name = format!("{} {}", first_name, last_name);
            
            // Choose random starting container
            let containers = self.astronomical_data.get_object_containers();
            let container = containers.choose(&mut self.rng).unwrap().clone();
            
            // Position near the container
            let random_offset = Vector3::new(
                self.rng.random_range(-1000.0..1000.0),
                self.rng.random_range(-1000.0..1000.0),
                self.rng.random_range(-1000.0..1000.0),
            );
            let position = container.position + random_offset;
            
            // Random starting vehicle
            let vehicle = self.generate_random_vehicle();
            
            // Create actor with idle state
            let actor = Actor {
                id,
                name,
                position,
                rotation: Quaternion::identity(),
                current_system: container.system,
                current_container: Some(container.name.clone()),
                vehicle,
                state: ActorState::Idle { 
                    duration: Duration::from_secs(self.rng.random_range(60..300)), 
                    start_time: Instant::now()
                },
                wallet: self.rng.random_range(1000.0..50000.0),
                inventory: HashMap::new(),
                behavior_profile: self.generate_random_behavior_profile(),
            };
            
            self.actors.push(actor);
        }
    }
    
    fn generate_random_vehicle(&mut self) -> Vehicle {
        // Choose a random vehicle type with realistic speeds
        match self.rng.random_range(0..10) {
            0 => Vehicle::OnFoot { speed: self.rng.random_range(1.0..5.0) }, // 1-5 m/s walking/running
            1..=3 => {
                // Ground vehicle
                let model = match self.rng.random_range(0..5) {
                    0 => GroundVehicleType::PTV,      // Slow
                    1 => GroundVehicleType::Ursa,     // Medium, armored
                    2 => GroundVehicleType::Cyclone,  // Fast
                    3 => GroundVehicleType::Ranger,   // Motorcycle
                    _ => GroundVehicleType::Nox,      // Hover bike
                };
                
                // Speed ranges for ground vehicles in m/s
                let speed = match model {
                    GroundVehicleType::PTV => self.rng.random_range(10.0..15.0),
                    GroundVehicleType::Ursa => self.rng.random_range(15.0..25.0),
                    GroundVehicleType::Cyclone => self.rng.random_range(25.0..40.0),
                    GroundVehicleType::Ranger => self.rng.random_range(30.0..45.0),
                    GroundVehicleType::Nox => self.rng.random_range(40.0..60.0),
                };
                
                Vehicle::GroundVehicle { model, speed }
            },
            _ => {
                // Spacecraft
                let model = match self.rng.random_range(0..8) {
                    0 => SpacecraftType::Aurora,
                    1 => SpacecraftType::Avenger,
                    2 => SpacecraftType::Cutlass,
                    3 => SpacecraftType::Freelancer,
                    4 => SpacecraftType::Constellation,
                    5 => SpacecraftType::Carrack,
                    6 => SpacecraftType::Hammerhead,
                    _ => SpacecraftType::Bengal,
                };
                
                // Speed ranges for spacecraft (regular speed in m/s)
                let speed = match model {
                    SpacecraftType::Aurora => self.rng.random_range(100.0..150.0),
                    SpacecraftType::Avenger => self.rng.random_range(150.0..200.0),
                    SpacecraftType::Cutlass => self.rng.random_range(120.0..180.0),
                    SpacecraftType::Freelancer => self.rng.random_range(100.0..160.0),
                    SpacecraftType::Constellation => self.rng.random_range(80.0..150.0),
                    SpacecraftType::Carrack => self.rng.random_range(70.0..130.0),
                    SpacecraftType::Hammerhead => self.rng.random_range(60.0..120.0),
                    SpacecraftType::Bengal => self.rng.random_range(50.0..100.0),
                };
                
                // Quantum travel speeds in km/s (much faster)
                let quantum_speed = match model {
                    SpacecraftType::Aurora => self.rng.random_range(150.0..200.0),
                    SpacecraftType::Avenger => self.rng.random_range(180.0..220.0),
                    SpacecraftType::Cutlass => self.rng.random_range(170.0..210.0),
                    SpacecraftType::Freelancer => self.rng.random_range(160.0..200.0),
                    SpacecraftType::Constellation => self.rng.random_range(200.0..250.0),
                    SpacecraftType::Carrack => self.rng.random_range(220.0..280.0),
                    SpacecraftType::Hammerhead => self.rng.random_range(180.0..230.0),
                    SpacecraftType::Bengal => self.rng.random_range(150.0..200.0),
                };
                
                Vehicle::Spacecraft { model, speed, quantum_speed: quantum_speed * 1000.0 } // Convert to m/s
            }
        }
    }
    
    fn generate_random_behavior_profile(&mut self) -> BehaviorProfile {
        // Generate random behavior profile with normalized weights
        let explorer = self.rng.random_range(0.0..1.0);
        let trader = self.rng.random_range(0.0..1.0);
        let miner = self.rng.random_range(0.0..1.0);
        let combat = self.rng.random_range(0.0..1.0);
        let social = self.rng.random_range(0.0..1.0);
        
        // Normalize to ensure they add up to 1.0
        let total = explorer + trader + miner + combat + social;
        BehaviorProfile {
            explorer_tendency: explorer / total,
            trader_tendency: trader / total,
            miner_tendency: miner / total,
            combat_tendency: combat / total,
            social_tendency: social / total,
        }
    }
    
    fn run(&mut self, duration: Duration, time_step: Duration) {
        println!("Starting simulation with {} actors", self.actors.len());
        let start_time = Instant::now();
        let mut last_update = start_time;
        
        // Main simulation loop
        while start_time.elapsed() < duration {
            let now = Instant::now();
            let elapsed = now.duration_since(last_update);
            
            if elapsed >= time_step {
                self.simulation_time += elapsed.as_secs_f64();
                self.update(elapsed);
                last_update = now;
                
                // Print status every few seconds
                if self.simulation_time % 1.0 < elapsed.as_secs_f64() {
                    self.print_status();
                }
            }
            
            // Avoid burning CPU
            thread::sleep(Duration::from_millis(10));
        }
        
        println!("Simulation completed after {} seconds", start_time.elapsed().as_secs());
    }
    
    fn update(&mut self, elapsed: Duration) {
        // Update positions of all celestial bodies
        self.update_celestial_objects(elapsed);
        
        // Update each actor
        for i in 0..self.actors.len() {
            self.update_actor(i, elapsed);
        }
        
        // Check for interactions between actors
        self.handle_actor_interactions();
    }
    
    fn update_celestial_objects(&mut self, elapsed: Duration) {
        // Update position and rotation of all celestial bodies based on their rotational velocities
        // This would involve complex orbital mechanics in a full implementation
        
        let elapsed_seconds = elapsed.as_secs_f64();
        
        // First collect data about container positions to avoid borrow conflicts
        let container_data: Vec<(usize, Vector3, ContainerType, System, f64)> = 
            self.astronomical_data.containers
                .iter()
                .enumerate()
                .map(|(i, c)| (i, c.position, c.container_type, c.system, c.body_radius))
                .collect();
        
        // Now update each container
        for (i, container) in self.astronomical_data.containers.iter_mut().enumerate() {
            // Update rotation based on rotational velocity
            let rot_angle = container.rot_vel.z * elapsed_seconds;
            let rotation = Quaternion::from_euler(0.0, 0.0, rot_angle);
            container.rot_quat = rotation.multiply(&container.rot_quat);
            
            // For moons and satellites, update position based on orbital parameters
            if container.container_type == ContainerType::Moon {
                // Find parent planet using the pre-collected data
                if let Some(parent_data) = container_data.iter()
                    .filter(|(_, _, ctype, system, _)| 
                        *ctype == ContainerType::Planet && *system == container.system)
                    .min_by(|(_, pos_a, _, _, _), (_, pos_b, _, _, _)| {
                        let dist_a = pos_a.distance(&container.position);
                        let dist_b = pos_b.distance(&container.position);
                        dist_a.partial_cmp(&dist_b).unwrap_or(std::cmp::Ordering::Equal)
                    }) 
                {
                    let (_, parent_position, _, _, parent_radius) = parent_data;
                    
                    // Calculate new position based on orbit around parent
                    // Simplified circular orbit
                    let distance = container.position.distance(parent_position);
                    let orbital_period = 2.0 * std::f64::consts::PI * distance.sqrt() / 
                                       (6.67430e-11 * parent_radius.powi(3)).sqrt();
                    let angular_velocity = 2.0 * std::f64::consts::PI / orbital_period;
                    let angle = angular_velocity * elapsed_seconds;
                    
                    // Simple circular orbit update
                    let current_angle = (container.position.z - parent_position.z)
                                       .atan2(container.position.x - parent_position.x);
                    let new_angle = current_angle + angle;
                    
                    container.position.x = parent_position.x + distance * new_angle.cos();
                    container.position.z = parent_position.z + distance * new_angle.sin();
                }
            }
        }
    }
    
    fn update_actor(&mut self, actor_index: usize, elapsed: Duration) {
        // Get actor state to determine what action to take
        let actor_state = self.actors[actor_index].state.clone();
        
        // Handle state based on the cloned state
        match actor_state {
            ActorState::Idle { duration, start_time } => {
                if start_time.elapsed() >= duration {
                    // Transition to a new state after idle time is complete
                    let next_state = self.decide_next_activity(actor_index);
                    self.actors[actor_index].state = next_state;
                }
            },
            ActorState::Planning { destination } => {
                // Create a path to the destination
                let actor = &self.actors[actor_index];
                let path = self.plan_path(actor, destination.clone());
                
                if let Some(path_segments) = path {
                    // Transition to Traveling state
                    self.actors[actor_index].state = ActorState::Traveling { 
                        destination: destination,
                        path: path_segments,
                        current_segment_index: 0,
                        progress: 0.0
                    };
                } else {
                    // Path planning failed, go back to idle
                    self.actors[actor_index].state = ActorState::Idle { 
                        duration: Duration::from_secs(30), 
                        start_time: Instant::now() 
                    };
                    println!("Actor {} could not plan path to destination", self.actors[actor_index].name);
                }
            },
            ActorState::Traveling { 
                destination, 
                path, 
                current_segment_index, 
                progress 
            } => {
                // Continue traveling along the current path segment
                let current_segment = &path[current_segment_index];
                
                // Calculate distance traveled this update
                let actor = &self.actors[actor_index];
                let travel_speed = self.get_travel_speed(actor, &current_segment.travel_type);
                let distance_traveled = travel_speed * elapsed.as_secs_f64();
                
                // Update progress along current segment
                let new_progress = progress + (distance_traveled / current_segment.distance);
                
                if new_progress >= 1.0 {
                    // Completed this segment
                    if current_segment_index + 1 < path.len() {
                        // Move to next segment
                        self.actors[actor_index].position = current_segment.to.position;
                        self.actors[actor_index].state = ActorState::Traveling {
                            destination: destination,
                            path: path,
                            current_segment_index: current_segment_index + 1,
                            progress: 0.0
                        };
                    } else {
                        // Reached final destination
                        self.actors[actor_index].position = current_segment.to.position;
                        
                        // Update container reference
                        match &destination {
                            ActorDestination::PointOfInterest(poi_name) => {
                                // Set current container based on the POI
                                if let Some(poi) = self.astronomical_data.get_point_of_interest_by_name(poi_name) {
                                    self.actors[actor_index].current_container = poi.obj_container.clone();
                                }
                                
                                // Transition to Exploring state
                                self.actors[actor_index].state = ActorState::Exploring {
                                    poi: poi_name.clone(),
                                    duration: Duration::from_secs(self.rng.random_range(300..1800)),
                                    start_time: Instant::now()
                                };
                            },
                            ActorDestination::ObjectContainer(container_name) => {
                                self.actors[actor_index].current_container = Some(container_name.clone());
                                
                                // Transition to Idle state
                                self.actors[actor_index].state = ActorState::Idle {
                                    duration: Duration::from_secs(self.rng.random_range(60..300)),
                                    start_time: Instant::now()
                                };
                            },
                            ActorDestination::SpecificLocation { container, .. } => {
                                self.actors[actor_index].current_container = Some(container.clone());
                                
                                // Transition to Idle state
                                self.actors[actor_index].state = ActorState::Idle {
                                    duration: Duration::from_secs(self.rng.random_range(60..300)),
                                    start_time: Instant::now()
                                };
                            },
                            ActorDestination::OrbitalMarker { container, .. } => {
                                self.actors[actor_index].current_container = Some(container.clone());
                                
                                // Transition to Idle state
                                self.actors[actor_index].state = ActorState::Idle {
                                    duration: Duration::from_secs(self.rng.random_range(60..300)),
                                    start_time: Instant::now()
                                };
                            }
                        }
                    }
                } else {
                    // Continue along current segment
                    // Interpolate position between from and to points
                    let from_pos = &current_segment.from.position;
                    let to_pos = &current_segment.to.position;
                    
                    // Linear interpolation based on progress
                    self.actors[actor_index].position = Vector3::new(
                        from_pos.x + (to_pos.x - from_pos.x) * new_progress,
                        from_pos.y + (to_pos.y - from_pos.y) * new_progress,
                        from_pos.z + (to_pos.z - from_pos.z) * new_progress
                    );
                    
                    // Update rotation to face travel direction
                    let _direction = Vector3::new(
                        to_pos.x - from_pos.x,
                        to_pos.y - from_pos.y,
                        to_pos.z - from_pos.z
                    ).normalized();
                    
                    // Set the actor's rotation to face the travel direction
                    // (In a full implementation, we'd convert direction vector to quaternion)
                    
                    // Update state with new progress
                    self.actors[actor_index].state = ActorState::Traveling {
                        destination: destination,
                        path: path,
                        current_segment_index: current_segment_index,
                        progress: new_progress
                    };
                }
            },
            ActorState::Exploring { poi: _, duration, start_time } => {
                if start_time.elapsed() >= duration {
                    // Finished exploring, decide what to do next
                    let next_state = self.decide_next_activity(actor_index);
                    self.actors[actor_index].state = next_state;
                }
                // Could implement random movement around the POI area
            },
            ActorState::Trading { buy_location, sell_location, cargo, quantity, stage } => {
                match stage {
                    TradingStage::TravelingToBuy => {
                        // Check if we've already arrived (previous state change)
                        if let Some(current_container) = &self.actors[actor_index].current_container {
                            if current_container == &buy_location {
                                // We've arrived at buying location, start buying
                                self.actors[actor_index].state = ActorState::Trading {
                                    buy_location: buy_location,
                                    sell_location: sell_location,
                                    cargo: cargo,
                                    quantity: quantity,
                                    stage: TradingStage::Buying
                                };
                            } else {
                                // Need to travel to buying location
                                self.actors[actor_index].state = ActorState::Planning {
                                    destination: ActorDestination::PointOfInterest(buy_location)
                                };
                            }
                        }
                    },
                    TradingStage::Buying => {
                        // Simulate buying process
                        // Deduct money from wallet
                        let cost = self.calculate_cargo_price(&cargo, quantity, &buy_location);
                        if self.actors[actor_index].wallet >= cost {
                            self.actors[actor_index].wallet -= cost;
                            
                            // Add to inventory
                            *self.actors[actor_index].inventory.entry(cargo.clone()).or_insert(0.0) += quantity;
                            
                            // Move to next stage
                            self.actors[actor_index].state = ActorState::Trading {
                                buy_location: buy_location,
                                sell_location: sell_location,
                                cargo: cargo,
                                quantity: quantity,
                                stage: TradingStage::TravelingToSell
                            };
                        } else {
                            // Not enough money, go back to idle
                            self.actors[actor_index].state = ActorState::Idle {
                                duration: Duration::from_secs(60),
                                start_time: Instant::now()
                            };
                        }
                    },
                    TradingStage::TravelingToSell => {
                        // Check if we've already arrived (previous state change)
                        if let Some(current_container) = &self.actors[actor_index].current_container {
                            if current_container == &sell_location {
                                // We've arrived at selling location, start selling
                                self.actors[actor_index].state = ActorState::Trading {
                                    buy_location: buy_location,
                                    sell_location: sell_location,
                                    cargo: cargo,
                                    quantity: quantity,
                                    stage: TradingStage::Selling
                                };
                            } else {
                                // Need to travel to selling location
                                self.actors[actor_index].state = ActorState::Planning {
                                    destination: ActorDestination::PointOfInterest(sell_location)
                                };
                            }
                        }
                    },
                    TradingStage::Selling => {
                        // Simulate selling process
                        // Check inventory
                        if let Some(inv_quantity) = self.actors[actor_index].inventory.get_mut(&cargo) {
                            if *inv_quantity >= quantity {
                                // Remove from inventory
                                *inv_quantity -= quantity;
                                if *inv_quantity <= 0.0 {
                                    self.actors[actor_index].inventory.remove(&cargo);
                                }
                                
                                // Add money to wallet
                                let price = self.calculate_cargo_price(&cargo, quantity, &sell_location) * 1.2; // 20% profit
                                self.actors[actor_index].wallet += price;
                                
                                // Trading complete, go idle
                                self.actors[actor_index].state = ActorState::Idle {
                                    duration: Duration::from_secs(self.rng.random_range(60..300)),
                                    start_time: Instant::now()
                                };
                            }
                        } else {
                            // No inventory, go idle
                            self.actors[actor_index].state = ActorState::Idle {
                                duration: Duration::from_secs(60),
                                start_time: Instant::now()
                            };
                        }
                    }
                }
            },
            ActorState::Mining { location, resource, progress, duration } => {
                // Update mining progress
                let mining_rate = 0.05; // 5% progress per update
                let new_progress = progress + mining_rate * elapsed.as_secs_f64() / duration.as_secs_f64();
                
                if new_progress >= 1.0 {
                    // Mining complete
                    let amount = self.rng.random_range(10.0..50.0);
                    *self.actors[actor_index].inventory.entry(resource.clone()).or_insert(0.0) += amount;
                    
                    println!("Actor {} mined {:.1} units of {}", self.actors[actor_index].name, amount, resource);
                    
                    // Decide next activity
                    let next_state = self.decide_next_activity(actor_index);
                    self.actors[actor_index].state = next_state;
                } else {
                    // Continue mining
                    self.actors[actor_index].state = ActorState::Mining {
                        location: location,
                        resource: resource,
                        progress: new_progress,
                        duration: duration
                    };
                }
            },
            ActorState::Socializing { location: _, other_actors: _, duration, start_time } => {
                if start_time.elapsed() >= duration {
                    // Socializing complete
                    let next_state = self.decide_next_activity(actor_index);
                    self.actors[actor_index].state = next_state;
                }
                // Could implement social interactions between actors
            }
        }
    }
    
    fn handle_actor_interactions(&mut self) {
        // Find actors that are close to each other
        let mut interactions: Vec<(usize, usize)> = Vec::new();
        
        // Identify potential interactions (simplified)
        for i in 0..self.actors.len() {
            for j in (i+1)..self.actors.len() {
                let pos1 = &self.actors[i].position;
                let pos2 = &self.actors[j].position;
                
                let distance = pos1.distance(pos2);
                
                // Interact if close enough (50m)
                if distance < 50.0 {
                    interactions.push((i, j));
                }
            }
        }
        
        // Process interactions
        for (i, j) in interactions {
            // Only process if both are idle, exploring, or socializing
            let actor_i_state = &self.actors[i].state;
            let actor_j_state = &self.actors[j].state;
            
            let can_interact_i = matches!(actor_i_state, 
                ActorState::Idle {..} | ActorState::Exploring {..} | ActorState::Socializing {..});
            let can_interact_j = matches!(actor_j_state, 
                ActorState::Idle {..} | ActorState::Exploring {..} | ActorState::Socializing {..});
            
            if can_interact_i && can_interact_j {
                // Both can interact - decide based on social tendency
                let i_social = self.actors[i].behavior_profile.social_tendency;
                let j_social = self.actors[j].behavior_profile.social_tendency;
                
                // If both have high enough social tendency, they socialize
                if i_social > 0.3 && j_social > 0.3 && self.rng.random_bool(0.5) {
                    let current_location = if let Some(loc) = &self.actors[i].current_container {
                        loc.clone()
                    } else {
                        "space".to_string()
                    };
                    
                    // Set both to socializing state
                    let duration = Duration::from_secs(self.rng.random_range(300..1200));
                    
                    self.actors[i].state = ActorState::Socializing {
                        location: current_location.clone(),
                        other_actors: vec![j],
                        duration,
                        start_time: Instant::now()
                    };
                    
                    self.actors[j].state = ActorState::Socializing {
                        location: current_location,
                        other_actors: vec![i],
                        duration,
                        start_time: Instant::now()
                    };
                    
                    println!("Actors {} and {} are now socializing", 
                             self.actors[i].name, self.actors[j].name);
                }
            }
        }
    }
    
    fn calculate_cargo_price(&self, cargo: &str, quantity: f64, _location: &str) -> f64 {
        // Base prices per unit
        let base_prices = match cargo {
            "Titanium" => 20.0,
            "Laranite" => 30.0,
            "Agricium" => 27.0,
            "Medical Supplies" => 18.0,
            "Waste" => 0.5,
            "Scrap" => 1.2,
            _ => 10.0
        };
        
        // Apply location-based modifiers (no RNG to avoid mutable borrow)
        let location_modifier = 1.0;
        
        // Calculate final price
        base_prices * quantity * location_modifier
    }
    
    fn decide_next_activity(&self, actor_index: usize) -> ActorState {
        // Create a temporary RNG to avoid mutable borrow
        let mut temp_rng = rand::rng();
        
        // Weighted decision based on behavior profile
        let rand_val = temp_rng.random_range(0.0..1.0);
        let profile = &self.actors[actor_index].behavior_profile;
        
        // Cumulatively add up weights
        let mut cumulative = profile.explorer_tendency;
        if rand_val < cumulative {
            return self.create_exploration_activity(actor_index, &mut temp_rng);
        }
        
        cumulative += profile.trader_tendency;
        if rand_val < cumulative {
            return self.create_trading_activity(actor_index, &mut temp_rng);
        }
        
        cumulative += profile.miner_tendency;
        if rand_val < cumulative {
            return self.create_mining_activity(actor_index, &mut temp_rng);
        }
        
        cumulative += profile.combat_tendency;
        if rand_val < cumulative {
            // Combat not implemented in this version, fall back to exploration
            return self.create_exploration_activity(actor_index, &mut temp_rng);
        }
        
        // Default to socializing or idle
        if temp_rng.random_bool(0.3) {
            // 30% chance to just go idle
            return ActorState::Idle {
                duration: Duration::from_secs(temp_rng.random_range(60..300)),
                start_time: Instant::now()
            };
        } else {
            // Try to find someone to socialize with (simplified for now)
            return self.create_exploration_activity(actor_index, &mut temp_rng);
        }
    }
    
    fn create_exploration_activity(&self, _actor_index: usize, rng: &mut ThreadRng) -> ActorState {
        // Get reference to data needed
        let pois = self.astronomical_data.get_points_of_interest();
        let containers = self.astronomical_data.get_object_containers();
        
        if rng.random_bool(0.7) && !pois.is_empty() {
            // 70% chance to explore a POI
            let poi = pois.choose(rng).unwrap();
            
            ActorState::Planning {
                destination: ActorDestination::PointOfInterest(poi.name.clone())
            }
        } else if !containers.is_empty() {
            // 30% chance to explore a container
            let container = containers.choose(rng).unwrap();
            
            if container.container_type == ContainerType::Planet || 
               container.container_type == ContainerType::Moon {
                // For planets/moons, visit a random point on the surface
                let radius = container.body_radius * 1.05; // Just above surface
                let theta = rng.random_range(0.0..std::f64::consts::PI * 2.0);
                let phi = rng.random_range(0.0..std::f64::consts::PI);
                
                let x = radius * phi.sin() * theta.cos();
                let y = radius * phi.sin() * theta.sin();
                let z = radius * phi.cos();
                
                let surface_point = Vector3::new(
                    container.position.x + x,
                    container.position.y + y, 
                    container.position.z + z
                );
                
                ActorState::Planning {
                    destination: ActorDestination::SpecificLocation {
                        container: container.name.clone(),
                        position: surface_point
                    }
                }
            } else {
                // For other containers, just visit the container
                ActorState::Planning {
                    destination: ActorDestination::ObjectContainer(container.name.clone())
                }
            }
        } else {
            // Fallback if no valid destinations
            ActorState::Idle {
                duration: Duration::from_secs(rng.random_range(60..300)),
                start_time: Instant::now()
            }
        }
    }
    
    fn create_trading_activity(&self, actor_index: usize, rng: &mut ThreadRng) -> ActorState {
        // Consider cargo, prices, and profitability
        let actor = &self.actors[actor_index];
        
        // Only spacecraft can trade
        if !matches!(actor.vehicle, Vehicle::Spacecraft { .. }) {
            return self.create_exploration_activity(actor_index, rng);
        }
        
        // Get potential trading locations
        let trade_locations: Vec<&PointOfInterest> = self.astronomical_data.get_points_of_interest()
            .iter()
            .filter(|poi| {
                matches!(poi.poi_type, 
                    PoiType::OrbitalStation | 
                    PoiType::Spaceport |
                    PoiType::Outpost)
            })
            .collect();
        
        if trade_locations.len() < 2 {
            // Not enough trading locations
            return self.create_exploration_activity(actor_index, rng);
        }
        
        // Choose distinct buy and sell locations
        let buy_location = trade_locations.choose(rng).unwrap();
        let sell_location = loop {
            let loc = trade_locations.choose(rng).unwrap();
            if loc.name != buy_location.name {
                break loc;
            }
        };
        
        // Choose cargo type
        let cargo_types = ["Titanium", "Laranite", "Agricium", "Medical Supplies", "Waste", "Scrap"];
        let cargo = cargo_types.choose(rng).unwrap().to_string();
        
        // Choose quantity based on wallet
        let price_per_unit = self.calculate_cargo_price(&cargo, 1.0, &buy_location.name);
        let max_affordable = (actor.wallet * 0.8) / price_per_unit; // Use 80% of wallet
        let quantity = rng.random_range(1.0..max_affordable.max(1.0));
        
        ActorState::Trading {
            buy_location: buy_location.name.clone(),
            sell_location: sell_location.name.clone(),
            cargo,
            quantity,
            stage: TradingStage::TravelingToBuy
        }
    }
    
    fn create_mining_activity(&self, actor_index: usize, rng: &mut ThreadRng) -> ActorState {
        let actor = &self.actors[actor_index];
        
        // Find suitable mining locations
        let mining_locations: Vec<&PointOfInterest> = self.astronomical_data.get_points_of_interest()
            .iter()
            .filter(|poi| {
                poi.poi_type == PoiType::AsteroidBelt || 
                poi.class.contains("mining")
            })
            .collect();
        
        if mining_locations.is_empty() {
            // No mining locations available
            return self.create_exploration_activity(actor_index, rng);
        }
        
        // Choose random mining location
        let location = mining_locations.choose(rng).unwrap();
        
        // Choose resource type
        let resources = ["Gold", "Copper", "Aluminum", "Diamond", "Corundum", "Quantanium"];
        let resource = resources.choose(rng).unwrap().to_string();
        
        // If we're already at the mining location, start mining
        if let Some(current_location) = &actor.current_container {
            if location.obj_container.as_ref() == Some(current_location) {
                return ActorState::Mining {
                    location: location.name.clone(),
                    resource,
                    progress: 0.0,
                    duration: Duration::from_secs(rng.random_range(300..900)), // 5-15 minutes
                };
            }
        }
        
        // Travel to mining location first
        ActorState::Planning {
            destination: ActorDestination::PointOfInterest(location.name.clone())
        }
    }
    
    fn get_travel_speed(&self, actor: &Actor, travel_type: &TravelType) -> f64 {
        match (travel_type, &actor.vehicle) {
            (TravelType::Quantum, Vehicle::Spacecraft { quantum_speed, .. }) => {
                *quantum_speed
            },
            (TravelType::Sublight, Vehicle::Spacecraft { speed, .. }) => {
                *speed
            },
            (TravelType::Planetary, Vehicle::Spacecraft { speed, .. }) => {
                *speed * 0.5 // Slower in atmosphere
            },
            (TravelType::Planetary, Vehicle::GroundVehicle { speed, .. }) => {
                *speed
            },
            (TravelType::Planetary, Vehicle::OnFoot { speed }) => {
                *speed
            },
            // Fallback cases
            (_, Vehicle::OnFoot { speed }) => *speed,
            (_, Vehicle::GroundVehicle { speed, .. }) => *speed,
        }
    }
    
    fn plan_path(&self, actor: &Actor, destination: ActorDestination) -> Option<Vec<PathSegment>> {
        // Get current position
        let current_position = actor.position;
        
        // Get destination position
        let destination_position = match &destination {
            ActorDestination::PointOfInterest(name) => {
                if let Some(poi) = self.astronomical_data.get_point_of_interest_by_name(name) {
                    poi.position
                } else {
                    return None; // POI not found
                }
            },
            ActorDestination::ObjectContainer(name) => {
                if let Some(container) = self.astronomical_data.get_object_container_by_name(name) {
                    container.position
                } else {
                    return None; // Container not found
                }
            },
            ActorDestination::SpecificLocation { position, .. } => {
                *position
            },
            ActorDestination::OrbitalMarker { container, marker } => {
                if let Some(container_obj) = self.astronomical_data.get_object_container_by_name(container) {
                    // Simplified orbital marker position
                    // In a real implementation, we'd compute this based on the container and marker ID
                    let marker_num = marker.chars().last().unwrap_or('1').to_digit(10).unwrap_or(1) as f64;
                    let angle = marker_num * (std::f64::consts::PI / 3.0);
                    let om_position = Vector3::new(
                        container_obj.position.x + container_obj.om_radius * angle.cos(),
                        container_obj.position.y,
                        container_obj.position.z + container_obj.om_radius * angle.sin()
                    );
                    om_position
                } else {
                    return None; // Container not found
                }
            }
        };
        
        // Determine if quantum travel is possible
        let can_use_quantum = matches!(actor.vehicle, Vehicle::Spacecraft { .. });
        let distance = current_position.distance(&destination_position);
        
        let mut path_segments = Vec::new();
        
        // Get current container
        let current_container_opt = if let Some(container_name) = &actor.current_container {
            self.astronomical_data.get_object_container_by_name(container_name)
        } else {
            None
        };
        
        // Get destination container
        let destination_container_opt = match &destination {
            ActorDestination::PointOfInterest(name) => {
                if let Some(poi) = self.astronomical_data.get_point_of_interest_by_name(name) {
                    if let Some(container_name) = &poi.obj_container {
                        self.astronomical_data.get_object_container_by_name(container_name)
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
            ActorDestination::ObjectContainer(name) => {
                self.astronomical_data.get_object_container_by_name(name)
            },
            ActorDestination::SpecificLocation { container, .. } => {
                self.astronomical_data.get_object_container_by_name(container)
            },
            ActorDestination::OrbitalMarker { container, .. } => {
                self.astronomical_data.get_object_container_by_name(container)
            }
        };
        
        // Determine travel type based on distance and vehicles
        // Simplified path planning logic
        if distance > 10000.0 && can_use_quantum {
            // Long distance - use quantum travel if available
            let from_point = PathPoint {
                name: "Origin".to_string(),
                position: current_position,
                point_type: NavNodeType::Origin
            };
            
            let to_point = PathPoint {
                name: "Destination".to_string(),
                position: destination_position,
                point_type: NavNodeType::Destination
            };
            
            path_segments.push(PathSegment {
                from: from_point,
                to: to_point,
                distance,
                travel_type: TravelType::Quantum,
                estimated_time: distance / self.get_travel_speed(actor, &TravelType::Quantum),
                direction: self.calculate_direction(&current_position, &destination_position),
                obstruction: None,
                is_obstruction_bypass: false
            });
        } else {
            // Shorter distance - use sublight travel
            // Check if we need to transition between containers
            if current_container_opt != destination_container_opt {
                // Need to exit current container if any
                if let Some(current_container) = current_container_opt {
                    // Calculate exit point from current container (e.g., to orbit)
                    let exit_distance = current_container.body_radius * 1.5;
                    let dir = (destination_position - current_container.position).normalized();
                    let exit_point = current_container.position + dir * exit_distance;
                    
                    
                    let from_point = PathPoint {
                        name: "Origin".to_string(),
                        position: current_position,
                        point_type: NavNodeType::Origin
                    };
                    
                    let exit_path_point = PathPoint {
                        name: format!("{} Orbit", current_container.name),
                        position: exit_point,
                        point_type: NavNodeType::Intermediate
                    };
                    
                    // Add segment to exit current container
                    let exit_distance = current_position.distance(&exit_point);
                    path_segments.push(PathSegment {
                        from: from_point,
                        to: exit_path_point.clone(),
                        distance: exit_distance,
                        travel_type: TravelType::Planetary,
                        estimated_time: exit_distance / self.get_travel_speed(actor, &TravelType::Planetary),
                        direction: self.calculate_direction(&current_position, &exit_point),
                        obstruction: None,
                        is_obstruction_bypass: false
                    });
                    
                    // If destination has a container, add entry segment
                    if let Some(dest_container) = destination_container_opt {
                        // Add segment to approach destination container
                        let approach_point =
                            dest_container.position
                            + (destination_position - dest_container.position).normalized().scale(
                                dest_container.body_radius * 1.5
                            );
                        
                        let approach_path_point = PathPoint {
                            name: format!("{} Approach", dest_container.name),
                            position: approach_point,
                            point_type: NavNodeType::Intermediate
                        };
                        
                        // Segment from current container exit to destination container approach
                        let approach_distance = exit_point.distance(&approach_point);
                        path_segments.push(PathSegment {
                            from: exit_path_point,
                            to: approach_path_point.clone(),
                            distance: approach_distance,
                            travel_type: if can_use_quantum && approach_distance > 10000.0 {
                                TravelType::Quantum
                            } else {
                                TravelType::Sublight
                            },
                            estimated_time: approach_distance / self.get_travel_speed(
                                actor, 
                                if can_use_quantum && approach_distance > 10000.0 {
                                    &TravelType::Quantum
                                } else {
                                    &TravelType::Sublight
                                }
                            ),
                            direction: self.calculate_direction(&exit_point, &approach_point),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                        
                        // Final segment to destination
                        let dest_point = PathPoint {
                            name: "Destination".to_string(),
                            position: destination_position,
                            point_type: NavNodeType::Destination
                        };
                        
                        let final_distance = approach_point.distance(&destination_position);
                        path_segments.push(PathSegment {
                            from: approach_path_point,
                            to: dest_point,
                            distance: final_distance,
                            travel_type: TravelType::Planetary,
                            estimated_time: final_distance / self.get_travel_speed(actor, &TravelType::Planetary),
                            direction: self.calculate_direction(&approach_point, &destination_position),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                    } else {
                        // Destination is in open space
                        let dest_point = PathPoint {
                            name: "Destination".to_string(),
                            position: destination_position,
                            point_type: NavNodeType::Destination
                        };
                        
                        let final_distance = exit_point.distance(&destination_position);
                        path_segments.push(PathSegment {
                            from: exit_path_point,
                            to: dest_point,
                            distance: final_distance,
                            travel_type: if can_use_quantum && final_distance > 10000.0 {
                                TravelType::Quantum
                            } else {
                                TravelType::Sublight
                            },
                            estimated_time: final_distance / self.get_travel_speed(
                                actor, 
                                if can_use_quantum && final_distance > 10000.0 {
                                    &TravelType::Quantum
                                } else {
                                    &TravelType::Sublight
                                }
                            ),
                            direction: self.calculate_direction(&exit_point, &destination_position),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                    }
                } else {
                    // Starting in open space, going to a container
                    if let Some(dest_container) = destination_container_opt {
                        // Add segment to approach destination container
                        let approach_point = dest_container.position
                            + (destination_position - dest_container.position).normalized().scale(
                                dest_container.body_radius * 1.5
                            );
                        
                        let from_point = PathPoint {
                            name: "Origin".to_string(),
                            position: current_position,
                            point_type: NavNodeType::Origin
                        };
                        
                        let approach_path_point = PathPoint {
                            name: format!("{} Approach", dest_container.name),
                            position: approach_point,
                            point_type: NavNodeType::Intermediate
                        };
                        
                        // Segment from origin to destination container approach
                        let approach_distance = current_position.distance(&approach_point);
                        path_segments.push(PathSegment {
                            from: from_point,
                            to: approach_path_point.clone(),
                            distance: approach_distance,
                            travel_type: if can_use_quantum && approach_distance > 10000.0 {
                                TravelType::Quantum
                            } else {
                                TravelType::Sublight
                            },
                            estimated_time: approach_distance / self.get_travel_speed(actor, &TravelType::Planetary),
                            direction: self.calculate_direction(&current_position, &approach_point),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                        
                        // Final segment to destination
                        let dest_point = PathPoint {
                            name: "Destination".to_string(),
                            position: destination_position,
                            point_type: NavNodeType::Destination
                        };
                        
                        let final_distance = approach_point.distance(&destination_position);
                        path_segments.push(PathSegment {
                            from: approach_path_point,
                            to: dest_point,
                            distance: final_distance,
                            travel_type: TravelType::Planetary,
                            estimated_time: final_distance / self.get_travel_speed(actor, &TravelType::Planetary),
                            direction: self.calculate_direction(&approach_point, &destination_position),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                    } else {
                        // Both origin and destination are in open space
                        let from_point = PathPoint {
                            name: "Origin".to_string(),
                            position: current_position,
                            point_type: NavNodeType::Origin
                        };
                        
                        let dest_point = PathPoint {
                            name: "Destination".to_string(),
                            position: destination_position,
                            point_type: NavNodeType::Destination
                        };
                        
                        path_segments.push(PathSegment {
                            from: from_point,
                            to: dest_point,
                            distance,
                            travel_type: if can_use_quantum && distance > 10000.0 {
                                TravelType::Quantum
                            } else {
                                TravelType::Sublight
                            },
                            estimated_time: distance / self.get_travel_speed(
                                actor, 
                                if can_use_quantum && distance > 10000.0 {
                                    &TravelType::Quantum
                                } else {
                                    &TravelType::Sublight
                                }
                            ),
                            direction: self.calculate_direction(&current_position, &destination_position),
                            obstruction: None,
                            is_obstruction_bypass: false
                        });
                    }
                }
            } else {
                // Same container or both in open space - direct path
                let from_point = PathPoint {
                    name: "Origin".to_string(),
                    position: current_position,
                    point_type: NavNodeType::Origin
                };
                
                let dest_point = PathPoint {
                    name: "Destination".to_string(),
                    position: destination_position,
                    point_type: NavNodeType::Destination
                };
                
                // Determine appropriate travel type
                let travel_type = if current_container_opt.is_some() {
                    // Within a container - use planetary travel
                    TravelType::Planetary
                } else if can_use_quantum && distance > 10000.0 {
                    // Long distance in space with quantum capability
                    TravelType::Quantum
                } else {
                    // Default to sublight travel
                    TravelType::Sublight
                };
                
                path_segments.push(PathSegment {
                    from: from_point,
                    to: dest_point,
                    distance,
                    travel_type,
                    estimated_time: distance / self.get_travel_speed(actor, &travel_type),
                    direction: self.calculate_direction(&current_position, &destination_position),
                    obstruction: None,
                    is_obstruction_bypass: false
                });
            }
        }
        
        if path_segments.is_empty() {
            None
        } else {
            Some(path_segments)
        }
    }
    
    fn calculate_direction(&self, from: &Vector3, to: &Vector3) -> EulerAngles {
        // Calculate direction vector
        let direction = to - from;
        
        // Convert to Euler angles
        // Yaw (rotation around Y axis)
        let yaw = direction.z.atan2(direction.x).to_degrees();
        
        // Pitch (rotation around X axis)
        let pitch = (-direction.y).asin().to_degrees();
        
        // Roll (not calculated from direction vector, set to 0)
        let roll = 0.0;
        
        EulerAngles::new(pitch, yaw, roll)
    }
    
    fn print_status(&self) {
        // Print summary of simulation status with fancy ASCII formatting
        println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
        println!("║                     SPACE NAVIGATION SIMULATION SYSTEM                       ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        println!("║ Simulation Time: {:.1}s                                                      ║", self.simulation_time);
        println!("║ Active Actors: {}                                                            ║", self.actors.len());
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        
        // Count actors by state
        let mut state_counts = HashMap::new();
        for actor in &self.actors {
            let state_name = match &actor.state {
                ActorState::Idle { .. } => "Idle",
                ActorState::Planning { .. } => "Planning",
                ActorState::Traveling { .. } => "Traveling",
                ActorState::Exploring { .. } => "Exploring",
                ActorState::Trading { .. } => "Trading",
                ActorState::Mining { .. } => "Mining",
                ActorState::Socializing { .. } => "Socializing",
            };
            *state_counts.entry(state_name).or_insert(0) += 1;
        }
        
        // Count actors by vehicle type
        let mut vehicle_counts = HashMap::new();
        for actor in &self.actors {
            let vehicle_type = match &actor.vehicle {
                Vehicle::OnFoot { .. } => "On Foot",
                Vehicle::GroundVehicle { model, .. } => match model {
                    GroundVehicleType::Cyclone => "Cyclone",
                    GroundVehicleType::Ursa => "Ursa",
                    GroundVehicleType::PTV => "PTV",
                    GroundVehicleType::Ranger => "Ranger",
                    GroundVehicleType::Nox => "Nox",
                },
                Vehicle::Spacecraft { model, .. } => match model {
                    SpacecraftType::Aurora => "Aurora",
                    SpacecraftType::Avenger => "Avenger",
                    SpacecraftType::Cutlass => "Cutlass",
                    SpacecraftType::Freelancer => "Freelancer",
                    SpacecraftType::Constellation => "Constellation",
                    SpacecraftType::Carrack => "Carrack",
                    SpacecraftType::Hammerhead => "Hammerhead",
                    SpacecraftType::Bengal => "Bengal",
                },
            };
            *vehicle_counts.entry(vehicle_type).or_insert(0) += 1;
        }
        
        // Print state counts in a nice table
        println!("║ ACTOR STATES                                                                 ║");
        println!("╠═══════════════╦════════╦═══════════╦═══════════╦═════════╦════════╦═════════╣");
        println!("║     IDLE      ║ PLANNING║ TRAVELING ║ EXPLORING ║ TRADING ║ MINING ║ SOCIAL  ║");
        println!("╠═══════════════╬════════╬═══════════╬═══════════╬═════════╬════════╬═════════╣");
        println!("║ {:^13} ║ {:^8} ║ {:^9} ║ {:^9} ║ {:^7} ║ {:^6} ║ {:^7} ║", 
            state_counts.get("Idle").unwrap_or(&0),
            state_counts.get("Planning").unwrap_or(&0),
            state_counts.get("Traveling").unwrap_or(&0),
            state_counts.get("Exploring").unwrap_or(&0),
            state_counts.get("Trading").unwrap_or(&0),
            state_counts.get("Mining").unwrap_or(&0),
            state_counts.get("Socializing").unwrap_or(&0)
        );
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        
        // Print vehicle distribution
        println!("║ VEHICLE DISTRIBUTION                                                         ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        
        // Ground vehicles
        println!("║ GROUND: On Foot: {:2}  |  Cyclone: {:2}  |  Ursa: {:2}  |  PTV: {:2}  |  Ranger: {:2}  |  Nox: {:2} ║",
            vehicle_counts.get("On Foot").unwrap_or(&0),
            vehicle_counts.get("Cyclone").unwrap_or(&0),
            vehicle_counts.get("Ursa").unwrap_or(&0),
            vehicle_counts.get("PTV").unwrap_or(&0),
            vehicle_counts.get("Ranger").unwrap_or(&0),
            vehicle_counts.get("Nox").unwrap_or(&0)
        );
        
        // Spacecraft
        println!("║ SPACE:  Aurora: {:2}  |  Avenger: {:2}  |  Cutlass: {:2}  |  Freelancer: {:2}  |  Constellation: {:2} ║",
            vehicle_counts.get("Aurora").unwrap_or(&0),
            vehicle_counts.get("Avenger").unwrap_or(&0),
            vehicle_counts.get("Cutlass").unwrap_or(&0),
            vehicle_counts.get("Freelancer").unwrap_or(&0),
            vehicle_counts.get("Constellation").unwrap_or(&0)
        );
        println!("║        Carrack: {:2}  |  Hammerhead: {:2}  |  Bengal: {:2}                                ║",
            vehicle_counts.get("Carrack").unwrap_or(&0),
            vehicle_counts.get("Hammerhead").unwrap_or(&0),
            vehicle_counts.get("Bengal").unwrap_or(&0)
        );
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        
        // Calculate location statistics
        let mut location_counts = HashMap::new();
        for actor in &self.actors {
            let location = match &actor.state {
                ActorState::Traveling { destination, .. } => {
                    match destination {
                        ActorDestination::PointOfInterest(name) => name.clone(),
                        ActorDestination::ObjectContainer(name) => name.clone(),
                        ActorDestination::SpecificLocation { container, .. } => container.clone(),
                        ActorDestination::OrbitalMarker { container, .. } => container.clone(),
                    }
                },
                ActorState::Exploring { poi, .. } => poi.clone(),
                ActorState::Trading { buy_location, .. } => buy_location.clone(),
                ActorState::Mining { location, .. } => location.clone(),
                ActorState::Socializing { location, .. } => location.clone(),
                _ => "Unknown".to_string(),
            };
            *location_counts.entry(location).or_insert(0) += 1;
        }
        
        // Print top 3 popular locations
        let mut locations: Vec<(String, &i32)> = location_counts.iter().map(|(k, v)| (k.clone(), v)).collect();
        locations.sort_by(|a, b| b.1.cmp(a.1));
        
        println!("║ POPULAR LOCATIONS                                                            ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        for (i, (location, count)) in locations.iter().take(3).enumerate() {
            println!("║ #{:<2} {:<30} with {:2} actors                                 ║", 
                i+1, 
                if location.len() > 30 { location[0..27].to_string() + "..." } else { location.clone() },
                count);
        }
        
        // Print detailed actor information
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        println!("║ DETAILED ACTOR INFORMATION                                                   ║");
        println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        
        // Print a few sample actors with more details
        let sample_size = std::cmp::min(5, self.actors.len());
        for i in 0..sample_size {
            let actor = &self.actors[i];
            
            // Get position information
            let position = &actor.position;
            let position_str = format!("({:.1}, {:.1}, {:.1})", position.x, position.y, position.z);
            
            // Get behavior profile summary
            let profile = &actor.behavior_profile;
            let dominant_trait = if profile.explorer_tendency >= profile.trader_tendency && 
                                   profile.explorer_tendency >= profile.miner_tendency &&
                                   profile.explorer_tendency >= profile.combat_tendency &&
                                   profile.explorer_tendency >= profile.social_tendency {
                "Explorer"
            } else if profile.trader_tendency >= profile.miner_tendency &&
                      profile.trader_tendency >= profile.combat_tendency &&
                      profile.trader_tendency >= profile.social_tendency {
                "Trader"
            } else if profile.miner_tendency >= profile.combat_tendency &&
                      profile.miner_tendency >= profile.social_tendency {
                "Miner"
            } else if profile.combat_tendency >= profile.social_tendency {
                "Fighter"
            } else {
                "Social"
            };
            
            let state_desc = match &actor.state {
                ActorState::Idle { duration, start_time } => {
                    let elapsed = start_time.elapsed();
                    let remaining = if elapsed < *duration {
                        duration.saturating_sub(elapsed)
                    } else {
                        Duration::from_secs(0)
                    };
                    format!("Idle for {}s more", remaining.as_secs())
                },
                ActorState::Planning { destination } => {
                    match destination {
                        ActorDestination::PointOfInterest(name) => 
                            format!("Planning trip to POI: {}", name),
                        ActorDestination::ObjectContainer(name) => 
                            format!("Planning trip to: {}", name),
                        ActorDestination::SpecificLocation { container, .. } => 
                            format!("Planning trip to location on: {}", container),
                        ActorDestination::OrbitalMarker { container, marker } => 
                            format!("Planning trip to {} around {}", marker, container),
                    }
                },
                ActorState::Traveling { destination, path, current_segment_index, progress } => {
                    let dest_name = match destination {
                        ActorDestination::PointOfInterest(name) => name.clone(),
                        ActorDestination::ObjectContainer(name) => name.clone(),
                        ActorDestination::SpecificLocation { container, .. } => 
                            format!("Location on {}", container),
                        ActorDestination::OrbitalMarker { container, marker } => 
                            format!("{} around {}", marker, container),
                    };
                    let travel_type = &path[*current_segment_index].travel_type;
                    format!("Traveling to {} ({:.0}%) using {:?}", 
                        if dest_name.len() > 20 { dest_name[0..17].to_string() + "..." } else { dest_name.clone() },
                        progress * 100.0, 
                        travel_type)
                },
                ActorState::Exploring { poi, duration, start_time } => {
                    let elapsed = start_time.elapsed();
                    let remaining = if elapsed < *duration {
                        duration.saturating_sub(elapsed)
                    } else {
                        Duration::from_secs(0)
                    };
                    let poi_name = if poi.len() > 20 { poi[0..17].to_string() + "..." } else { poi.clone() };
                    format!("Exploring {} for {}s more", poi_name, remaining.as_secs())
                },
                ActorState::Trading { stage, cargo, quantity, buy_location, sell_location, .. } => {
                    let cargo_name = if cargo.len() > 10 { cargo[0..7].to_string() + "..." } else { cargo.clone() };
                    let buy_loc = if buy_location.len() > 15 { buy_location[0..12].to_string() + "..." } else { buy_location.clone() };
                    let sell_loc = if sell_location.len() > 15 { sell_location[0..12].to_string() + "..." } else { sell_location.clone() };
                    
                    match stage {
                        TradingStage::TravelingToBuy => 
                            format!("Going to buy {:.1} {} at {}", quantity, cargo_name, buy_loc),
                        TradingStage::Buying => 
                            format!("Buying {:.1} {} at {}", quantity, cargo_name, buy_loc),
                        TradingStage::TravelingToSell => 
                            format!("Transporting {:.1} {} from {} to {}", quantity, cargo_name, buy_loc, sell_loc),
                        TradingStage::Selling => 
                            format!("Selling {:.1} {} at {}", quantity, cargo_name, sell_loc),
                    }
                },
                ActorState::Mining { resource, location, progress, .. } => {
                    let res_name = if resource.len() > 15 { resource[0..12].to_string() + "..." } else { resource.clone() };
                    let loc_name = if location.len() > 15 { location[0..12].to_string() + "..." } else { location.clone() };
                    format!("Mining {} at {} ({:.0}%)", res_name, loc_name, progress * 100.0)
                },
                ActorState::Socializing { location, other_actors, duration, start_time } => {
                    let elapsed = start_time.elapsed();
                    let remaining = if elapsed < *duration {
                        duration.saturating_sub(elapsed)
                    } else {
                        Duration::from_secs(0)
                    };
                    let loc_name = if location.len() > 15 { location[0..12].to_string() + "..." } else { location.clone() };
                    format!("Socializing with {} others at {} for {}s more", 
                            other_actors.len(), loc_name, remaining.as_secs())
                },
            };
            
            // Truncate long position strings
            let truncated_pos = if position_str.len() > 35 {
                format!("({:.1e}, {:.1e}, {:.1e})", position.x, position.y, position.z)
            } else {
                position_str
            };
            
            let vehicle_desc = match &actor.vehicle {
                Vehicle::OnFoot { speed } => format!("On foot ({}m/s)", speed),
                Vehicle::GroundVehicle { model, speed } => match model {
                    GroundVehicleType::Cyclone => format!("Cyclone buggy ({}m/s)", speed),
                    GroundVehicleType::Ursa => format!("Ursa rover ({}m/s)", speed),
                    GroundVehicleType::PTV => format!("PTV cart ({}m/s)", speed),
                    GroundVehicleType::Ranger => format!("Ranger motorcycle ({}m/s)", speed),
                    GroundVehicleType::Nox => format!("Nox hover bike ({}m/s)", speed),
                },
                Vehicle::Spacecraft { model, speed, quantum_speed } => match model {
                    SpacecraftType::Aurora => format!("Aurora ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Avenger => format!("Avenger ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Cutlass => format!("Cutlass ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Freelancer => format!("Freelancer ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Constellation => format!("Constellation ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Carrack => format!("Carrack ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Hammerhead => format!("Hammerhead ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                    SpacecraftType::Bengal => format!("Bengal ({}m/s, QT: {}km/s)", speed, quantum_speed/1000.0),
                },
            };
            
            println!("║ ACTOR: {:^20} | TYPE: {:^8} | POS: {:^20} ║", actor.name, dominant_trait, truncated_pos);
            println!("║ VEHICLE: {:^70} ║", vehicle_desc);
            println!("║ STATUS: {:^70} ║", state_desc);
            println!("╠══════════════════════════════════════════════════════════════════════════════╣");
        }
        
        println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    }
}
