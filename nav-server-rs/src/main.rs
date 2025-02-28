use actix_web::{web, App, HttpServer, HttpResponse, Responder, middleware::Logger, error::ErrorInternalServerError};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::io::Write;
use env_logger::Builder;
use log::LevelFilter;

use starnav;

// Re-export from the existing lib.rs
use starnav::coordinate_transform::{CoordinateTransformer, TransformDirection};
use starnav::nav_planner::NavigationPlanner;
use starnav::types::{AstronomicalDataProvider, NavigationPlan, PointOfInterest, StaticAstronomicalData, Vector3};
use starnav::types::ObjectContainer;
use starnav::types;

// Import from lib.rs
pub struct SpaceNavigationSystem<T: AstronomicalDataProvider> {
    planner: NavigationPlanner<T>,
    data_provider: Arc<T>,
}

impl<T: AstronomicalDataProvider> SpaceNavigationSystem<T> {
    pub fn new(data_provider: T) -> Self {
        let data_provider = Arc::new(data_provider);
        let planner = NavigationPlanner::new(Arc::clone(&data_provider));
        
        Self {
            planner,
            data_provider,
        }
    }
    
    pub fn set_position_local(&mut self, container_name: &str, local_x: f64, local_y: f64, local_z: f64) {
        self.planner.set_position_local(container_name, local_x, local_y, local_z);
    }
    
    pub fn update_position(&mut self, x: f64, y: f64, z: f64) {
        self.planner.update_position(x, y, z);
    }
    
    pub fn plan_navigation(&self, destination_name: &str) -> Option<NavigationPlan> {
        self.planner.plan_navigation(destination_name)
    }
    
    pub fn format_navigation_instructions(&self, plan: &NavigationPlan) -> String {
        self.planner.format_navigation_instructions(plan)
    }
    
    pub fn find_nearby_pois(&self, limit: usize) -> Vec<types::NamedDistance> {
        self.planner.find_nearby_pois(limit)
    }
    
    pub fn plan_navigation_to_coordinates(
        &self, 
        container_name: Option<&str>, 
        pos_x: f64, 
        pos_y: f64, 
        pos_z: f64,
        system: Option<&str>
    ) -> Option<NavigationPlan> {
        self.planner.plan_navigation_to_coordinates(container_name, pos_x, pos_y, pos_z, system)
    }
}

pub fn create_navigation_system(poi_data: Vec<PointOfInterest>, container_data: Vec<ObjectContainer>) -> SpaceNavigationSystem<StaticAstronomicalData> {
    let data_provider = StaticAstronomicalData::new(poi_data, container_data);
    SpaceNavigationSystem::new(data_provider)
}

// Define application state to hold the navigation system
struct AppState {
    nav_system: Arc<Mutex<starnav::SpaceNavigationSystem<types::StaticAstronomicalData>>>,
}

// Helper methods to reduce code duplication
impl AppState {
    /// Get a lock on the navigation system, returning an error response if it fails
    fn lock_nav_system(&self) -> Result<std::sync::MutexGuard<starnav::SpaceNavigationSystem<types::StaticAstronomicalData>>, actix_web::Error> {
        self.nav_system.lock().map_err(|e| {
            log::error!("Failed to acquire lock: {}", e);
            ErrorInternalServerError("Server error: could not access navigation system")
        })
    }
    
    /// Set position in the navigation system based on provided parameters
    fn set_position(&self, container: Option<&str>, x: f64, y: f64, z: f64) -> Result<std::sync::MutexGuard<starnav::SpaceNavigationSystem<types::StaticAstronomicalData>>, actix_web::Error> {
        let mut nav_system = self.lock_nav_system()?;
        
        if let Some(container_name) = container {
            nav_system.set_position_local(container_name, x, y, z);
        } else {
            nav_system.update_position(x, y, z);
        }
        
        Ok(nav_system)
    }
}

// Response structs
// ---------------------------------------------------------------------------

// Response format for POI listing
#[derive(Serialize)]
struct PoiResponse {
    name: String,
    distance: f64,
    type_name: String,
    position: Vector3,
    container: Option<String>,
}

// Response format for compass data
#[derive(Serialize)]
struct CompassResponse {
    pitch: f64,
    yaw: f64,
    roll: f64,
    distance: f64,
}

// Response format for coordinate transformations
#[derive(Serialize)]
struct CoordinateResponse {
    x: f64,
    y: f64,
    z: f64,
    container: Option<String>,
}

// Response for current position
#[derive(Serialize)]
struct PositionResponse {
    x: f64,
    y: f64,
    z: f64,
    container: Option<String>,
    system: Option<String>,
}

// Response for line of sight check
#[derive(Serialize)]
struct LineOfSightResponse {
    has_line_of_sight: bool,
    obstruction: Option<String>,
    distance_to_obstruction: Option<f64>,
}

// Request queries
// ---------------------------------------------------------------------------

fn default_limit() -> usize {
    10
}

// Query parameters for nearby POIs endpoint
#[derive(Deserialize)]
struct NearbyQuery {
    container: Option<String>,
    x: f64,
    y: f64,
    z: f64,
    #[serde(default = "default_limit")]
    limit: usize,
}

// Query parameters for navigation endpoints
#[derive(Deserialize)]
struct NavigateQuery {
    from_container: Option<String>,
    x: f64,
    y: f64,
    z: f64,
    destination: String,
}

// Query parameters for compass endpoint
#[derive(Deserialize)]
struct CompassQuery {
    container: Option<String>,
    x: f64,
    y: f64,
    z: f64,
    target: String,
}

// Query parameters for coordinate navigation endpoints
#[derive(Deserialize)]
struct NavigateToCoordinatesQuery {
    from_container: Option<String>,
    from_x: f64,
    from_y: f64,
    from_z: f64,
    to_container: Option<String>,
    to_x: f64,
    to_y: f64,
    to_z: f64,
    system: Option<String>,
}

// Query parameters for global-to-local coordinate transformation
#[derive(Deserialize)]
struct GlobalToLocalQuery {
    x: f64,
    y: f64, 
    z: f64,
    container: String,
}

// Query parameters for local-to-global coordinate transformation
#[derive(Deserialize)]
struct LocalToGlobalQuery {
    container: String,
    local_x: f64,
    local_y: f64,
    local_z: f64,
}

// Query parameters for finding POIs within a radius
#[derive(Deserialize)]
struct RadiusQuery {
    container: Option<String>,
    x: f64,
    y: f64,
    z: f64,
    radius: f64,
}

// Query parameters for line of sight check
#[derive(Deserialize)]
struct LineOfSightQuery {
    from_container: Option<String>,
    from_x: f64,
    from_y: f64,
    from_z: f64,
    to_container: Option<String>,
    to_x: f64,
    to_y: f64,
    to_z: f64,
}

// Query parameters for container resolution
#[derive(Deserialize)]
struct ResolveContainerQuery {
    x: f64,
    y: f64,
    z: f64,
}

// Query parameters for filtering POIs and containers
#[derive(Deserialize)]
struct FilterQuery {
    system: Option<String>,
    r#type: Option<String>,
}

// API Handlers
// ---------------------------------------------------------------------------

// Handler functions for POI operations
mod poi_handlers {
    use super::*;

    // Handler for listing nearby POIs
    pub async fn get_nearby_pois(
        query: web::Query<NearbyQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        let limit = std::cmp::min(query.limit, 50); // Cap at 50
        
        // Set position and get nav system
        let nav_system = data.set_position(query.container.as_deref(), query.x, query.y, query.z)?;
        
        // Get nearby POIs
        let nearby = nav_system.find_nearby_pois(limit);
        
        // Get data provider to fetch POI details
        let data_provider = nav_system.data_provider.clone();
        
        // Convert to response format with additional details
        let response: Vec<PoiResponse> = nearby.into_iter()
            .map(|poi| create_poi_response(&poi, &data_provider))
            .collect();
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Handler for finding POIs within a specific radius
    pub async fn find_pois_in_radius(
        query: web::Query<RadiusQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(query.container.as_deref(), query.x, query.y, query.z)?;
        
        // Get POIs within radius
        let nearby = nav_system.find_nearby_pois_in_radius(query.radius);
        
        // Get data provider to fetch POI details
        let data_provider = nav_system.data_provider.clone();
        
        // Convert to response format with additional details
        let response: Vec<PoiResponse> = nearby.into_iter()
            .map(|poi| create_poi_response(&poi, &data_provider))
            .collect();
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Helper to create a POI response from a named distance
    fn create_poi_response(poi: &types::NamedDistance, data_provider: &types::StaticAstronomicalData) -> PoiResponse {
        // Try to find full POI data to get type and container
        let full_poi = data_provider.get_point_of_interest_by_name(&poi.name);
        let type_name = full_poi.map_or_else(
            || "Unknown".to_string(), 
            |p| format!("{:?}", p.poi_type)
        );
        let container = full_poi.and_then(|p| p.obj_container.clone());
        
        let position = full_poi.map_or_else(
            || Vector3::new(0.0, 0.0, 0.0),
            |p| p.position
        );

        PoiResponse {
            name: poi.name.clone(),
            distance: poi.distance,
            type_name,
            position,
            container,
        }
    }

    // Handler for getting filtered POIs and containers
    pub async fn get_filtered_data(
        query: web::Query<FilterQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        let data_provider = &*nav_system.data_provider;
        
        // Get all POIs and containers
        let all_pois = data_provider.pois.clone();
        let all_containers = data_provider.containers.clone();
        
        // Filter POIs
        let filtered_pois: Vec<_> = all_pois.iter()
            .filter(|poi| {
                // Filter by system if specified
                if let Some(ref system) = query.system {
                    // Use the system property directly instead of deriving from position
                    if poi.system.to_string().to_lowercase() != *system.to_lowercase() {
                        return false;
                    }
                }
                
                // Filter by container if specified
                if let Some(ref container_type) = query.r#type {
                    if let Some(container_name) = &poi.obj_container {
                        if let Some(container) = data_provider.get_object_container_by_name(container_name) {
                            if format!("{:?}", container.container_type) != *container_type {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else if *container_type != "None" {
                        return false;
                    }
                }
                
                // Filter by POI type if specified
                if let Some(ref poi_type) = query.r#type {
                    if format!("{:?}", poi.poi_type) != *poi_type {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();
        
        // Filter containers
        let filtered_containers: Vec<_> = all_containers.iter()
            .filter(|container| {
                // Filter by system if specified
                if let Some(ref system) = query.system {
                    // Use the system property directly instead of deriving from position
                    if container.system.to_string().to_lowercase() != *system.to_lowercase() {
                        return false;
                    }
                }
                
                // Filter by container type if specified
                if let Some(ref container_type) = query.r#type {
                    if format!("{:?}", container.container_type).to_lowercase() != *container_type.to_lowercase() {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();
        
        // Create response structure
        #[derive(Serialize)]
        struct FilteredDataResponse {
            pois: Vec<PointOfInterest>,
            containers: Vec<ObjectContainer>,
        }
        
        let response = FilteredDataResponse {
            pois: filtered_pois,
            containers: filtered_containers,
        };
        
        Ok(HttpResponse::Ok().json(response))
    }
}

// Handler functions for navigation operations
mod navigation_handlers {
    use super::*;

    // Handler for JSON navigation plan
    pub async fn navigate_json(
        query: web::Query<NavigateQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(query.from_container.as_deref(), query.x, query.y, query.z)?;
        
        // Plan navigation
        match nav_system.plan_navigation(&query.destination) {
            Some(plan) => Ok(HttpResponse::Ok().json(plan)),
            None => Ok(HttpResponse::BadRequest().body("Could not generate navigation plan"))
        }
    }

    // Handler for plain text navigation plan
    pub async fn navigate_text(
        query: web::Query<NavigateQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(query.from_container.as_deref(), query.x, query.y, query.z)?;
        
        // Plan navigation
        match nav_system.plan_navigation(&query.destination) {
            Some(plan) => {
                let instructions = nav_system.format_navigation_instructions(&plan);
                Ok(HttpResponse::Ok().content_type("text/plain").body(instructions))
            },
            None => Ok(HttpResponse::BadRequest().body("Could not generate navigation plan"))
        }
    }

    // Handler for compass data
    pub async fn compass(
        query: web::Query<CompassQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(query.container.as_deref(), query.x, query.y, query.z)?;
        
        // Plan navigation to target (which gives us direction)
        match nav_system.plan_navigation(&query.target) {
            Some(plan) => {
                // Extract direction from first segment
                if plan.segments.is_empty() {
                    return Ok(HttpResponse::BadRequest().body("Navigation plan has no segments"));
                }
                
                let first_segment = &plan.segments[0];
                
                let response = CompassResponse {
                    pitch: first_segment.direction.pitch,
                    yaw: first_segment.direction.yaw,
                    roll: first_segment.direction.roll,
                    distance: first_segment.distance,
                };
                
                Ok(HttpResponse::Ok().json(response))
            },
            None => Ok(HttpResponse::BadRequest().body("Could not generate navigation plan"))
        }
    }

    // Handler for JSON navigation plan to coordinates
    pub async fn navigate_to_coordinates_json(
        query: web::Query<NavigateToCoordinatesQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(
            query.from_container.as_deref(), 
            query.from_x, 
            query.from_y, 
            query.from_z
        )?;
        
        // Plan navigation to coordinates
        let plan = plan_to_coordinates(&nav_system, &query);
        
        match plan {
            Some(plan) => Ok(HttpResponse::Ok().json(plan)),
            None => Ok(HttpResponse::BadRequest().body("Could not generate navigation plan"))
        }
    }

    // Handler for plain text navigation plan to coordinates
    pub async fn navigate_to_coordinates_text(
        query: web::Query<NavigateToCoordinatesQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Set position and get nav system
        let nav_system = data.set_position(
            query.from_container.as_deref(), 
            query.from_x, 
            query.from_y, 
            query.from_z
        )?;
        
        // Plan navigation to coordinates
        let plan = plan_to_coordinates(&nav_system, &query);
        
        match plan {
            Some(plan) => {
                let instructions = nav_system.format_navigation_instructions(&plan);
                Ok(HttpResponse::Ok().content_type("text/plain").body(instructions))
            },
            None => Ok(HttpResponse::BadRequest().body("Could not generate navigation plan"))
        }
    }

    // Helper function to plan navigation to coordinates
    fn plan_to_coordinates(
        nav_system: &starnav::SpaceNavigationSystem<types::StaticAstronomicalData>, 
        query: &NavigateToCoordinatesQuery
    ) -> Option<NavigationPlan> {
        if let Some(container) = query.to_container.as_deref() {
            // Plan using container coordinates
            nav_system.plan_navigation_to_coordinates(
                Some(container),
                query.to_x,
                query.to_y,
                query.to_z,
                None
            )
        } else {
            // Plan using global coordinates with system name
            nav_system.plan_navigation_to_coordinates(
                None,
                query.to_x,
                query.to_y,
                query.to_z,
                query.system.as_deref()
            )
        }
    }
}

// Handler functions for coordinate operations
mod coordinate_handlers {
    use super::*;

    // Handler for translating global coordinates to local coordinates within a container
    pub async fn global_to_local(
        query: web::Query<GlobalToLocalQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        
        // Get the container from the data provider
        let container = match nav_system.data_provider.get_object_container_by_name(&query.container) {
            Some(c) => c,
            None => return Ok(HttpResponse::BadRequest().body(format!("Container '{}' not found", query.container)))
        };
        
        // Create input position vector
        let position = Vector3::new(query.x, query.y, query.z);
        
        // Use coordinate transformer with proper TransformDirection
        let transformer = CoordinateTransformer::new();
        let local_coords = transformer.transform_coordinates(
            &position,
            &container,
            TransformDirection::ToLocal,
        );
        
        let response = CoordinateResponse {
            x: local_coords.x,
            y: local_coords.y,
            z: local_coords.z,
            container: Some(query.container.clone()),
        };
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Handler for translating local coordinates to global coordinates
    pub async fn local_to_global(
        query: web::Query<LocalToGlobalQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        
        // Get the container from the data provider
        let container = match nav_system.data_provider.get_object_container_by_name(&query.container) {
            Some(c) => c,
            None => return Ok(HttpResponse::BadRequest().body(format!("Container '{}' not found", query.container)))
        };
        
        // Create input position vector
        let local_position = Vector3::new(query.local_x, query.local_y, query.local_z);
        
        // Use coordinate transformer with proper TransformDirection
        let transformer = CoordinateTransformer::new();
        let global_coords = transformer.transform_coordinates(
            &local_position,
            &container,
            TransformDirection::ToGlobal,
        );
        
        let response = CoordinateResponse {
            x: global_coords.x,
            y: global_coords.y,
            z: global_coords.z,
            container: None,
        };
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Handler for resolving which container a position is in
    pub async fn resolve_container(
        query: web::Query<ResolveContainerQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        
        // Position vector
        let position = Vector3::new(query.x, query.y, query.z);
        
        // Resolve container
        let container = nav_system.resolve_container_at_position(&position);
        
        let response = CoordinateResponse {
            x: position.x,
            y: position.y,
            z: position.z,
            container: container.map(|c| c.name),
        };
        
        Ok(HttpResponse::Ok().json(response))
    }
}

// Handler functions for position and environmental operations
mod position_handlers {
    use starnav::types::System;

    use super::*;

    // Handler for getting current position and system
    pub async fn get_current_position(
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        
        // Get current position
        let position = match nav_system.get_current_position() {
            Some(pos) => pos,
            None => return Ok(HttpResponse::BadRequest().body("Current position not set"))
        };
        
        // Get current container
        let container = nav_system.get_current_object_container()
            .map(|c| c.name.clone());
        
        // Get current system directly from the current object container
        let system = nav_system.get_current_object_container()
            .map(|c| c.system.to_string())
            .or_else(|| Some(System::Stanton.to_string()));
        
        let response = PositionResponse {
            x: position.x,
            y: position.y,
            z: position.z,
            container,
            system,
        };
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Handler for checking line of sight between two points
    pub async fn check_line_of_sight(
        query: web::Query<LineOfSightQuery>,
        data: web::Data<AppState>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Get nav system
        let nav_system = data.lock_nav_system()?;
        
        // Create transformer for coordinates
        let transformer = CoordinateTransformer::new();
        
        // Process positions
        let from_position = process_position(
            query.from_container.as_deref(), 
            query.from_x, 
            query.from_y, 
            query.from_z, 
            &nav_system,
            &transformer
        )?;
        
        let to_position = process_position(
            query.to_container.as_deref(), 
            query.to_x, 
            query.to_y, 
            query.to_z, 
            &nav_system,
            &transformer
        )?;
        
        // Check line of sight
        let los_result = nav_system.check_line_of_sight(&from_position, &to_position);
        
        // Calculate distance to obstruction if there is one
        let distance_to_obstruction = if !los_result.has_los && los_result.obstruction.is_some() {
            let obstruction_pos = los_result.obstruction.as_ref().map(|obj| &obj.position);
            obstruction_pos.map(|pos| {
                let dx = pos.x - from_position.x;
                let dy = pos.y - from_position.y;
                let dz = pos.z - from_position.z;
                (dx * dx + dy * dy + dz * dz).sqrt()
            })
        } else {
            None
        };
        
        let response = LineOfSightResponse {
            has_line_of_sight: los_result.has_los,
            obstruction: los_result.obstruction.map(|obj| obj.name.clone()),
            distance_to_obstruction,
        };
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Helper function to process a position (local or global)
    fn process_position(
        container: Option<&str>,
        x: f64,
        y: f64,
        z: f64,
        nav_system: &starnav::SpaceNavigationSystem<types::StaticAstronomicalData>,
        transformer: &CoordinateTransformer,
    ) -> Result<Vector3, actix_web::Error> {
        if let Some(container_name) = container {
            // Get the container from the data provider
            let container_obj = match nav_system.data_provider.get_object_container_by_name(container_name) {
                Some(c) => c,
                None => return Err(actix_web::error::ErrorBadRequest(format!("Container '{}' not found", container_name)))
            };
            
            // Local coordinates
            let local_pos = Vector3::new(x, y, z);
            
            // Transform to global
            Ok(transformer.transform_coordinates(
                &local_pos,
                &container_obj,
                TransformDirection::ToGlobal,
            ))
        } else {
            // Already global coordinates
            Ok(Vector3::new(x, y, z))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    setup_logging();
    
    // Load navigation data
    let (pois, containers) = load_navigation_data()?;
    
    // Create navigation system
    let nav_system = starnav::create_navigation_system(pois, containers);
    let app_state = web::Data::new(AppState {
        nav_system: Arc::new(Mutex::new(nav_system)),
    });
    
    // Define server address and port
    let server_addr = "127.0.0.1";
    let server_port = 8080;
    
    // Start HTTP server
    log::info!("Starting Space Navigation API server on http://{}:{}", server_addr, server_port);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .service(
                web::scope("/api")
                    // POI endpoints
                    .route("/poi/nearby", web::get().to(poi_handlers::get_nearby_pois))
                    .route("/poi/in-radius", web::get().to(poi_handlers::find_pois_in_radius))
                    .route("/data/filtered", web::get().to(poi_handlers::get_filtered_data))
                    
                    // Navigation endpoints
                    .route("/navigate/json", web::get().to(navigation_handlers::navigate_json))
                    .route("/navigate/text", web::get().to(navigation_handlers::navigate_text))
                    .route("/navigate/coordinates/json", web::get().to(navigation_handlers::navigate_to_coordinates_json))
                    .route("/navigate/coordinates/text", web::get().to(navigation_handlers::navigate_to_coordinates_text))
                    .route("/compass", web::get().to(navigation_handlers::compass))
                    
                    // Coordinate endpoints
                    .route("/coordinates/global-to-local", web::get().to(coordinate_handlers::global_to_local))
                    .route("/coordinates/local-to-global", web::get().to(coordinate_handlers::local_to_global))
                    .route("/resolve/container", web::get().to(coordinate_handlers::resolve_container))
                    
                    // Position and environment endpoints
                    .route("/position/current", web::get().to(position_handlers::get_current_position))
                    .route("/check/line-of-sight", web::get().to(position_handlers::check_line_of_sight))
            )
    })
    .bind((server_addr, server_port))?
    .run()
    .await
}

// Utility functions
// ---------------------------------------------------------------------------

/// Setup logging with proper format and level
fn setup_logging() {
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
}

/// Load navigation data from JSON files
fn load_navigation_data() -> std::io::Result<(Vec<PointOfInterest>, Vec<ObjectContainer>)> {
    let poi_path = "pois.json";
    let container_path = "objContainers.json";
    
    log::info!("Loading navigation data from {} and {}", poi_path, container_path);
    match starnav::data_loader::load_navigation_data(poi_path, container_path) {
        Ok(data) => {
            log::info!("Successfully loaded {} points of interest and {} object containers", 
                       data.0.len(), data.1.len());
            Ok(data)
        },
        Err(e) => {
            log::error!("Error loading data: {}", e);
            Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Data loading error: {}", e)))
        }
    }
}