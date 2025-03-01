use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;

use serde::{Deserialize, Serialize};

/// 3D vector representation
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3 {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn distance(&self, other: &Vector3) -> f64 {
        ((self.x - other.x).powi(2) + 
         (self.y - other.y).powi(2) + 
         (self.z - other.z).powi(2)).sqrt()
    }
    
    pub fn normalized(&self) -> Self {
        let magnitude = (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        if magnitude < 1e-6 {
            return *self; // Return unchanged if near-zero magnitude
        }
        Self {
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }
}

/// Quaternion representation for rotations
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Quaternion {
    pub w: f64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Quaternion {
    pub fn new(w: f64, x: f64, y: f64, z: f64) -> Self {
        Self { w, x, y, z }
    }
    
    pub fn identity() -> Self {
        Self { w: 1.0, x: 0.0, y: 0.0, z: 0.0 }
    }
    
    pub fn conjugate(&self) -> Self {
        Self {
            w: self.w,
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
    
    pub fn normalize(&self) -> Self {
        let magnitude = (self.w.powi(2) + self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        Self {
            w: self.w / magnitude,
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }
    
    pub fn multiply(&self, other: &Quaternion) -> Self {
        Self {
            w: self.w * other.w - self.x * other.x - self.y * other.y - self.z * other.z,
            x: self.w * other.x + self.x * other.w + self.y * other.z - self.z * other.y,
            y: self.w * other.y - self.x * other.z + self.y * other.w + self.z * other.x,
            z: self.w * other.z + self.x * other.y - self.y * other.x + self.z * other.w,
        }
    }
    
    pub fn rotate_vector(&self, vector: &Vector3) -> Vector3 {
        // Convert vector to quaternion form (0, vx, vy, vz)
        let vec_quat = Quaternion::new(0.0, vector.x, vector.y, vector.z);
        
        // Perform rotation: q * v * q^-1
        let result = self.multiply(&vec_quat).multiply(&self.conjugate());
        
        Vector3::new(result.x, result.y, result.z)
    }
    
    /// Convert Euler angles (in degrees) to quaternion
    pub fn from_euler(pitch: f64, yaw: f64, roll: f64) -> Self {
        // Convert to radians
        let pitch_rad = pitch.to_radians();
        let yaw_rad = yaw.to_radians();
        let roll_rad = roll.to_radians();
        
        // Calculate half angles
        let cx = (pitch_rad / 2.0).cos();
        let sx = (pitch_rad / 2.0).sin();
        let cy = (yaw_rad / 2.0).cos();
        let sy = (yaw_rad / 2.0).sin();
        let cz = (roll_rad / 2.0).cos();
        let sz = (roll_rad / 2.0).sin();
        
        // ZYX convention for Euler to quaternion conversion
        let w = cx * cy * cz + sx * sy * sz;
        let x = sx * cy * cz - cx * sy * sz;
        let y = cx * sy * cz + sx * cy * sz;
        let z = cx * cy * sz - sx * sy * cz;
        
        Self { w, x, y, z }.normalize()
    }
    
    /// Convert quaternion to Euler angles (in degrees)
    pub fn to_euler(&self) -> (f64, f64, f64) {
        // Normalize the quaternion to ensure valid results
        let q = self.normalize();
        
        // Roll (z-axis rotation)
        let sinr_cosp = 2.0 * (q.w * q.x + q.y * q.z);
        let cosr_cosp = 1.0 - 2.0 * (q.x * q.x + q.y * q.y);
        let roll = sinr_cosp.atan2(cosr_cosp);
        
        // Pitch (x-axis rotation)
        let sinp = 2.0 * (q.w * q.y - q.z * q.x);
        let pitch = if sinp.abs() >= 1.0 {
            std::f64::consts::FRAC_PI_2.copysign(sinp) // Use 90 degrees if out of range
        } else {
            sinp.asin()
        };
        
        // Yaw (y-axis rotation)
        let siny_cosp = 2.0 * (q.w * q.z + q.x * q.y);
        let cosy_cosp = 1.0 - 2.0 * (q.y * q.y + q.z * q.z);
        let yaw = siny_cosp.atan2(cosy_cosp);
        
        // Convert to degrees
        (
            pitch.to_degrees(),
            yaw.to_degrees(),
            roll.to_degrees()
        )
    }
}

/// Euler angles in degrees
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EulerAngles {
    pub pitch: f64,
    pub yaw: f64,
    pub roll: f64,
}

impl EulerAngles {
    pub fn new(pitch: f64, yaw: f64, roll: f64) -> Self {
        Self { pitch, yaw, roll }
    }
}

/// Solar system identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum System {
    Stanton,
    Pyro,
    Nyx, 
    Ellis,
    Sol,
    // Add other star systems as needed
}

impl System {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Stanton" => Some(System::Stanton),
            "Pyro" => Some(System::Pyro),
            "Nyx" => Some(System::Nyx),
            "Ellis" => Some(System::Ellis),
            "Sol" => Some(System::Sol),
            _ => None,
        }
    }
}

impl fmt::Display for System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            System::Stanton => write!(f, "Stanton"),
            System::Pyro => write!(f, "Pyro"),
            System::Nyx => write!(f, "Nyx"),
            System::Ellis => write!(f, "Ellis"),
            System::Sol => write!(f, "Sol"),
        }
    }
}

/// Container type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerType {
    JumpPoint,
    Lagrange,
    Moon,
    NavalStation,
    Planet,
    RefineryStation,
    RestStop,
    Star,
}

impl ContainerType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "JumpPoint" => Some(ContainerType::JumpPoint),
            "Lagrange" => Some(ContainerType::Lagrange),
            "Moon" => Some(ContainerType::Moon),
            "NavalStation" => Some(ContainerType::NavalStation),
            "Planet" => Some(ContainerType::Planet),
            "RefineryStation" => Some(ContainerType::RefineryStation),
            "RestStop" => Some(ContainerType::RestStop),
            "Star" => Some(ContainerType::Star),
            _ => None,
        }
    }
}

/// Point of interest classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PoiType {
    AnimalArea,
    AsteroidBelt,
    Cave,
    ColonialBunker,
    ColonialOutpost,
    CommArray,
    DerelictOutpost,
    DerelictSettlement,
    DistributionCenter,
    Druglab,
    Easteregg,
    Event,
    ForwardOperatingBase,
    JumpPoint,
    LandingZone,
    Missing,
    MissionArea,
    ObjectContainer,
    OrbitalStation,
    Outpost,
    Picoball,
    Prison,
    Racetrack,
    RacetrackCommunity,
    River,
    Scrapyard,
    Spaceport,
    StashHouse,
    UndergroundFacility,
    Unknown,
    Wreck,
}

impl PoiType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "AnimalArea" => Some(PoiType::AnimalArea),
            "AsteroidBelt" => Some(PoiType::AsteroidBelt),
            "Cave" => Some(PoiType::Cave),
            "ColonialBunker" => Some(PoiType::ColonialBunker),
            "ColonialOutpost" => Some(PoiType::ColonialOutpost),
            "CommArray" => Some(PoiType::CommArray),
            "DerelictOutpost" => Some(PoiType::DerelictOutpost),
            "DerelictSettlement" => Some(PoiType::DerelictSettlement),
            "DistributionCenter" => Some(PoiType::DistributionCenter),
            "Druglab" => Some(PoiType::Druglab),
            "Easteregg" => Some(PoiType::Easteregg),
            "Event" => Some(PoiType::Event),
            "ForwardOperatingBase" => Some(PoiType::ForwardOperatingBase),
            "JumpPoint" => Some(PoiType::JumpPoint),
            "LandingZone" => Some(PoiType::LandingZone),
            "missing" => Some(PoiType::Missing),
            "MissionArea" => Some(PoiType::MissionArea),
            "ObjectContainer" => Some(PoiType::ObjectContainer),
            "OrbitalStation" => Some(PoiType::OrbitalStation),
            "Outpost" => Some(PoiType::Outpost),
            "Picoball" => Some(PoiType::Picoball),
            "Prison" => Some(PoiType::Prison),
            "Racetrack" => Some(PoiType::Racetrack),
            "RacetrackCommunity" => Some(PoiType::RacetrackCommunity),
            "River" => Some(PoiType::River),
            "Scrapyard" => Some(PoiType::Scrapyard),
            "Spaceport" => Some(PoiType::Spaceport),
            "StashHouse" => Some(PoiType::StashHouse),
            "UndergroundFacility" => Some(PoiType::UndergroundFacility),
            "Unknown" => Some(PoiType::Unknown),
            "Wreck" => Some(PoiType::Wreck),
            _ => None,
        }
    }
}

/// Celestial body or station container
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectContainer {
    pub id: u32,
    pub system: System,
    pub container_type: ContainerType,
    pub name: String,
    pub internal_name: String,
    pub position: Vector3,
    pub rot_vel: Vector3,
    pub rot_adj: Vector3,
    pub rot_quat: Quaternion,
    pub body_radius: f64,
    pub om_radius: f64,
    pub grid_radius: f64,
}

impl ObjectContainer {
    pub fn new(
        id: u32,
        system: System,
        container_type: ContainerType,
        name: String,
        internal_name: String,
        position: Vector3,
        rot_vel: Vector3,
        rot_adj: Vector3,
        rot_quat: Quaternion,
        body_radius: f64,
        om_radius: f64,
        grid_radius: f64,
    ) -> Self {
        Self {
            id,
            system,
            container_type,
            name,
            internal_name,
            position,
            rot_vel,
            rot_adj,
            rot_quat,
            body_radius,
            om_radius,
            grid_radius,
        }
    }
}

/// Point of interest location
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PointOfInterest {
    pub id: u32,
    pub name: String,
    pub system: System,
    pub obj_container: Option<String>,
    pub poi_type: PoiType,
    pub class: String,
    pub position: Vector3,
    pub has_qt_marker: bool,
    pub date_added: Option<String>,
    pub comment: Option<String>,
    pub with_version: Option<String>,
}

impl PointOfInterest {
    pub fn new(
        id: u32,
        name: String,
        system: System,
        obj_container: Option<String>,
        poi_type: PoiType,
        class: String,
        position: Vector3,
        has_qt_marker: bool,
        date_added: Option<String>,
        comment: Option<String>,
        with_version: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            system,
            obj_container,
            poi_type,
            class,
            position,
            has_qt_marker,
            date_added,
            comment,
            with_version,
        }
    }
}

/// Path complexity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathComplexity {
    Direct,
    Simple,
    Complex,
}

impl fmt::Display for PathComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathComplexity::Direct => write!(f, "DIRECT"),
            PathComplexity::Simple => write!(f, "SIMPLE"),
            PathComplexity::Complex => write!(f, "COMPLEX"),
        }
    }
}

/// Travel method classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TravelType {
    Quantum,
    Sublight,
}

impl fmt::Display for TravelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TravelType::Quantum => write!(f, "QUANTUM TRAVEL"),
            TravelType::Sublight => write!(f, "SUBLIGHT"),
        }
    }
}

/// Entity types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    PointOfInterest,
    ObjectContainer,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::PointOfInterest => write!(f, "poi"),
            EntityType::ObjectContainer => write!(f, "container"),
        }
    }
}

impl EntityType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "poi" => Some(EntityType::PointOfInterest),
            "container" => Some(EntityType::ObjectContainer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Entity {
    PointOfInterest(PointOfInterest),
    ObjectContainer(ObjectContainer),
}


/// Navigation node types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NavNodeType {
    Origin,
    Destination,
    OrbitalMarker,
    QuantumMarker,
    Intermediate,
}

impl fmt::Display for NavNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NavNodeType::Origin => write!(f, "origin"),
            NavNodeType::Destination => write!(f, "destination"),
            NavNodeType::OrbitalMarker => write!(f, "om"),
            NavNodeType::QuantumMarker => write!(f, "qt_marker"),
            NavNodeType::Intermediate => write!(f, "intermediate"),
        }
    }
}

/// Navigation search direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchDirection {
    Forward,
    Backward,
    Both,
}

/// Enhanced navigation node for bidirectional pathfinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavNode {
    pub position: Vector3,
    pub parent_node: Option<Arc<NavNode>>,
    pub g_cost: f64,             // Cost from start to this node
    pub h_cost: f64,             // Estimated cost from this node to goal
    pub f_cost: f64,             // Total cost (g + h)
    pub node_type: NavNodeType,
    pub name: String,
    pub container_ref: Option<Arc<ObjectContainer>>,
    pub obstruction_path: bool,  // Flag for obstruction avoidance
    pub search_direction: SearchDirection,
}

impl NavNode {
    pub fn new(
        position: Vector3,
        node_type: NavNodeType,
        name: String,
        container_ref: Option<Arc<ObjectContainer>>,
    ) -> Self {
        Self {
            position,
            parent_node: None,
            g_cost: 0.0,
            h_cost: 0.0,
            f_cost: 0.0,
            node_type,
            name,
            container_ref,
            obstruction_path: false,
            search_direction: SearchDirection::Forward,
        }
    }
    
    pub fn calculate_f_cost(&mut self) {
        self.f_cost = self.g_cost + self.h_cost;
    }
    
    pub fn equals(&self, other: &NavNode) -> bool {
        // Consider nodes equal if they have the same position
        (self.position.x - other.position.x).abs() < 1e-6 &&
        (self.position.y - other.position.y).abs() < 1e-6 &&
        (self.position.z - other.position.z).abs() < 1e-6
    }
}

/// Path segment for navigation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSegment {
    pub from: PathPoint,
    pub to: PathPoint,
    pub distance: f64,
    pub travel_type: TravelType,
    pub estimated_time: f64,
    pub direction: EulerAngles,
    pub obstruction: Option<String>,
    pub is_obstruction_bypass: bool,
}

/// Point in a navigation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPoint {
    pub name: String,
    pub position: Vector3,
    pub point_type: NavNodeType,
}

/// Navigation plan with obstruction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationPlan {
    pub segments: Vec<PathSegment>,
    pub total_distance: f64,
    pub total_estimated_time: f64,
    pub quantum_jumps: u32,
    pub obstruction_detected: bool,
    pub obstructions: Vec<String>,
    pub path_complexity: PathComplexity,
    pub origin_container: Option<Arc<ObjectContainer>>,
}

/// Navigation result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationResult {
    pub distance: f64,
    pub direction: EulerAngles,
    pub eta: f64,
    pub angular_deviation: Option<f64>,
    pub closest_orbital_marker: Option<NamedDistance>,
    pub closest_qt_beacon: Option<NamedDistance>,
}

/// Named distance structure for references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedDistance {
    pub name: String,
    pub distance: f64,
}

/// Line of sight check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineOfSightResult {
    pub has_los: bool,
    pub obstruction: Option<Arc<ObjectContainer>>,
}

/// Meeting point for bidirectional search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeetingPoint {
    pub forward_node: Arc<NavNode>,
    pub backward_node: Arc<NavNode>,
    pub total_cost: f64,
}

/// Visibility edge for path planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityEdge {
    pub from_node: Arc<NavNode>,
    pub to_node: Arc<NavNode>,
    pub distance: f64,
    pub has_los: bool,
    pub obstruction: Option<Arc<ObjectContainer>>,
}

/// Data provider trait for astronomical database access
pub trait AstronomicalDataProvider {
    fn get_points_of_interest(&self) -> &[PointOfInterest];
    fn get_object_containers(&self) -> &[ObjectContainer];
    fn get_point_of_interest_by_name(&self, name: &str) -> Option<&PointOfInterest>;
    fn get_object_container_by_name(&self, name: &str) -> Option<&ObjectContainer>;
}

/// Default implementation of astronomical data provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAstronomicalData {
    pub pois: Vec<PointOfInterest>,
    pub containers: Vec<ObjectContainer>,
    pub poi_name_map: HashMap<String, usize>,
    pub container_name_map: HashMap<String, usize>,
}

impl StaticAstronomicalData {
    pub fn new(pois: Vec<PointOfInterest>, containers: Vec<ObjectContainer>) -> Self {
        let mut poi_name_map = HashMap::new();
        let mut container_name_map = HashMap::new();
        
        for (i, poi) in pois.iter().enumerate() {
            poi_name_map.insert(poi.name.clone(), i);
        }
        
        for (i, container) in containers.iter().enumerate() {
            container_name_map.insert(container.name.clone(), i);
        }
        
        Self {
            pois,
            containers,
            poi_name_map,
            container_name_map,
        }
    }
}

impl AstronomicalDataProvider for StaticAstronomicalData {
    fn get_points_of_interest(&self) -> &[PointOfInterest] {
        &self.pois
    }
    
    fn get_object_containers(&self) -> &[ObjectContainer] {
        &self.containers
    }
    
    fn get_point_of_interest_by_name(&self, name: &str) -> Option<&PointOfInterest> {
        self.poi_name_map.get(name).map(|&i| &self.pois[i])
    }
    
    fn get_object_container_by_name(&self, name: &str) -> Option<&ObjectContainer> {
        self.container_name_map.get(name).map(|&i| &self.containers[i])
    }
}