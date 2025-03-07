use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::f64::consts::PI;

use serde::{Deserialize, Serialize};

// Fundamental physical constants
const G: f64 = 6.67430e-11; // Gravitational constant (m³/kg·s²)
//const ASTRONOMICAL_UNIT: f64 = 149_597_870_700.0; // Astronomical Unit in meters
const EPSILON: f64 = 1e-10; // Numerical epsilon for floating-point comparisons

// System enumerations
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum System {
    Stanton,
    Pyro,
    Nyx,
    Ellis,
    Sol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum TravelType {
    Quantum,
    QuantumBoost,
    Hydrogen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum EntityType {
    PointOfInterest,
    ObjectContainer,
}

// Core data structures exactly matching specification
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Quaternion {
    pub w: f64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EulerAngles {
    pub pitch: f64,
    pub yaw: f64,
    pub roll: f64,
}

// Persistent data structures per specification
#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

// Additional structures for navigation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrbitalMarker {
    pub id: u32,
    pub name: String,
    pub container_id: u32,
    pub local_position: Vector3,
    pub global_position: Vector3,
}

// Navigation-related structures
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Waypoint {
    pub entity_id: u32,
    pub entity_type: EntityType,
    pub position: Vector3,
    pub arrival_time: f64,
    pub travel_type: TravelType,
    pub distance: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NavigationPath {
    pub waypoints: Vec<Waypoint>,
    pub total_distance: f64,
    pub total_time: f64,
    pub start_time: f64,
    pub propulsion_changes: Vec<(usize, TravelType)>,
    pub los_checks: Vec<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct NavigationConstraints {
    pub min_approach_distance: f64,
    pub prefer_distance: bool,
    pub prefer_segments: bool,
    pub prefer_safety: bool,
    pub buffer_distance: f64,
    pub max_hydrogen_distance: f64,
    pub avoid_atmospheres: bool,
    pub min_altitude: f64,
    pub safety_margin: f64,
}

// Keplerian orbital elements for precise celestial mechanics
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeplerianElements {
    pub semi_major_axis: f64,
    pub eccentricity: f64,
    pub inclination: f64,
    pub longitude_ascending_node: f64,
    pub argument_periapsis: f64,
    pub mean_anomaly_epoch: f64,
    pub orbital_period: f64,
    pub central_mass: f64,
}

// Motion types and models for dynamic entity behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MotionType {
    Static,
    Orbiting,
    Independent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum IndependentMotionType {
    Linear { 
        velocity: Vector3, 
        acceleration: Vector3 
    },
    Circular { 
        center: Vector3, 
        axis: Vector3, 
        angular_velocity: f64, 
        radius: f64 
    },
    Programmed { 
        waypoints: Vec<(Vector3, f64)>,
        current_index: usize,
        loop_motion: bool,
    },
    Bezier { 
        control_points: Vec<Vector3>,
        durations: Vec<f64>,
        current_segment: usize,
        current_segment_time: f64,
    },
    Stationary,
}

// Spatial indexing structures
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AABB {
    pub min: Vector3,
    pub max: Vector3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OctreeNode {
    pub aabb: AABB,
    pub center: Vector3,
    pub half_dimension: f64,
    pub entities: Vec<(u32, EntityType)>,
    pub children: Option<Box<[OctreeNode; 8]>>,
    pub depth: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BVHNode {
    pub aabb: AABB,
    pub entities: Vec<(u32, EntityType)>,
    pub left: Option<Box<BVHNode>>,
    pub right: Option<Box<BVHNode>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HybridSpatialIndex {
    pub octree_root: OctreeNode,
    pub bvh_regions: Vec<BVHNode>,
    pub entity_positions: HashMap<(u32, EntityType), Vector3>,
}

// A* pathfinding structures
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
struct PathNode {
    pub entity_id: u32,
    pub entity_type: EntityType,
    pub position: Vector3,
    pub g_score: f64,
    pub f_score: f64,
    pub parent: Option<usize>,
    pub travel_type: TravelType,
}

impl Eq for PathNode {}

impl PartialOrd for PathNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.f_score.partial_cmp(&self.f_score) // Reversed for min-heap
    }
}

impl Ord for PathNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.f_score.partial_cmp(&self.f_score)
            .unwrap_or(Ordering::Equal)
    }
}

// Internal computational state for derived properties
#[derive(Debug)]
struct ContainerState {
    pub atmosphere_radius: f64,
    pub safety_radius: f64,
    pub parent_id: Option<u32>,
    pub orbital_markers: Vec<u32>,
    pub mass: f64,
    pub orbital_elements: Option<KeplerianElements>,
    pub creation_time: f64,
    pub last_update_time: f64,
}

#[derive(Debug)]
pub struct PoiState {
    pub local_position: Vector3,
    pub parent_id: Option<u32>,
    pub motion_type: MotionType,
    pub independent_motion: Option<IndependentMotionType>,
    pub last_update_time: f64,
}

// Main navigation system
pub struct InterstellarNavigationSystem {
    // Persistent data collections
    pub containers: HashMap<u32, ObjectContainer>,
    pub pois: HashMap<u32, PointOfInterest>,
    pub orbital_markers: HashMap<u32, OrbitalMarker>,
    
    // Computational state
    container_states: HashMap<u32, ContainerState>,
    poi_states: HashMap<u32, PoiState>,
    
    // Spatial indexing
    spatial_index: HybridSpatialIndex,
    
    // Simulation parameters
    current_time: f64,
    origin_time: f64,
    last_position_update: f64,
    last_index_update: f64,
    
    // Navigation state
    active_paths: HashMap<u32, NavigationPath>,
    last_path_update: HashMap<u32, f64>,
    
    // Configuration
    default_constraints: NavigationConstraints,
}

/// Resolves entity global position accounting for parent-child relationships
pub fn resolve_entity_position(
    containers: &HashMap<u32, ObjectContainer>,
    pois: &HashMap<u32, PointOfInterest>,
    poi_states: &HashMap<u32, PoiState>,
    entity_id: u32,
    entity_type: EntityType
) -> Option<Vector3> {
    match entity_type {
        EntityType::ObjectContainer => {
            containers.get(&entity_id).map(|container| container.position.clone())
        },
        EntityType::PointOfInterest => {
            let poi = pois.get(&entity_id)?;
            let state = poi_states.get(&entity_id)?;
            
            if let (Some(parent_id), MotionType::Static) = (state.parent_id, state.motion_type) {
                if let Some(parent) = containers.get(&parent_id) {
                    let rotated = parent.rot_quat.rotate_vector(&state.local_position);
                    return Some(parent.position.add(&rotated));
                }
            }
            
            Some(poi.position.clone())
        },
    }
}

impl Vector3 {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }
    
    pub fn zero() -> Self {
        Self { x: 0.0, y: 0.0, z: 0.0 }
    }
    
    pub fn unit_x() -> Self {
        Self { x: 1.0, y: 0.0, z: 0.0 }
    }
    
    pub fn unit_y() -> Self {
        Self { x: 0.0, y: 1.0, z: 0.0 }
    }
    
    pub fn unit_z() -> Self {
        Self { x: 0.0, y: 0.0, z: 1.0 }
    }
    
    pub fn add(&self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
    
    pub fn sub(&self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }
    
    pub fn scale(&self, scalar: f64) -> Vector3 {
        Vector3 {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
    
    pub fn dot(&self, other: &Vector3) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }
    
    pub fn cross(&self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }
    
    pub fn magnitude(&self) -> f64 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }
    
    pub fn magnitude_squared(&self) -> f64 {
        self.x * self.x + self.y * self.y + self.z * self.z
    }
    
    pub fn distance(&self, other: &Vector3) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2) + (self.z - other.z).powi(2)).sqrt()
    }
    
    pub fn normalized(&self) -> Vector3 {
        let mag = self.magnitude();
        if mag < EPSILON {
            return Vector3::zero();
        }
        
        Vector3 {
            x: self.x / mag,
            y: self.y / mag,
            z: self.z / mag,
        }
    }
    
    pub fn lerp(&self, other: &Vector3, t: f64) -> Vector3 {
        Vector3 {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
            z: self.z + (other.z - self.z) * t,
        }
    }
    
    pub fn project_onto(&self, other: &Vector3) -> Vector3 {
        let other_norm = other.normalized();
        other_norm.scale(self.dot(&other_norm))
    }
    
    pub fn reject_from(&self, other: &Vector3) -> Vector3 {
        let projection = self.project_onto(other);
        self.sub(&projection)
    }
    
    pub fn rotate_around_axis(&self, axis: &Vector3, angle: f64) -> Vector3 {
        let axis_norm = axis.normalized();
        let cos_angle = angle.cos();
        let sin_angle = angle.sin();
        
        let term1 = self.scale(cos_angle);
        let term2 = axis_norm.cross(self).scale(sin_angle);
        let term3 = axis_norm.scale(axis_norm.dot(self) * (1.0 - cos_angle));
        
        term1.add(&term2).add(&term3)
    }
    
    pub fn negate(&self) -> Vector3 {
        Vector3 {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
    
    pub fn is_near_zero(&self) -> bool {
        self.magnitude_squared() < EPSILON * EPSILON
    }
    
    pub fn abs(&self) -> Vector3 {
        Vector3 {
            x: self.x.abs(),
            y: self.y.abs(),
            z: self.z.abs(),
        }
    }
    
    pub fn component_min(&self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x.min(other.x),
            y: self.y.min(other.y),
            z: self.z.min(other.z),
        }
    }
    
    pub fn component_max(&self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x.max(other.x),
            y: self.y.max(other.y),
            z: self.z.max(other.z),
        }
    }
}

impl Quaternion {
    pub fn new(w: f64, x: f64, y: f64, z: f64) -> Self {
        Self { w, x, y, z }
    }
    
    pub fn identity() -> Self {
        Self { w: 1.0, x: 0.0, y: 0.0, z: 0.0 }
    }
    
    pub fn from_axis_angle(axis: &Vector3, angle: f64) -> Self {
        let half_angle = angle / 2.0;
        let sin_half = half_angle.sin();
        let normalized = axis.normalized();
        
        Self {
            w: half_angle.cos(),
            x: normalized.x * sin_half,
            y: normalized.y * sin_half,
            z: normalized.z * sin_half,
        }
    }
    
    pub fn from_euler(euler: &EulerAngles) -> Self {
        let pitch_half = euler.pitch / 2.0;
        let yaw_half = euler.yaw / 2.0;
        let roll_half = euler.roll / 2.0;
        
        let cos_pitch = pitch_half.cos();
        let sin_pitch = pitch_half.sin();
        let cos_yaw = yaw_half.cos();
        let sin_yaw = yaw_half.sin();
        let cos_roll = roll_half.cos();
        let sin_roll = roll_half.sin();
        
        Self {
            w: cos_roll * cos_pitch * cos_yaw + sin_roll * sin_pitch * sin_yaw,
            x: sin_roll * cos_pitch * cos_yaw - cos_roll * sin_pitch * sin_yaw,
            y: cos_roll * sin_pitch * cos_yaw + sin_roll * cos_pitch * sin_yaw,
            z: cos_roll * cos_pitch * sin_yaw - sin_roll * sin_pitch * cos_yaw,
        }
    }
    
    pub fn magnitude(&self) -> f64 {
        (self.w * self.w + self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }
    
    pub fn normalize(&self) -> Self {
        let magnitude = self.magnitude();
        if magnitude < EPSILON {
            return Self::identity();
        }
        
        Self {
            w: self.w / magnitude,
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }
    
    pub fn conjugate(&self) -> Self {
        Self {
            w: self.w,
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
    
    pub fn inverse(&self) -> Self {
        // For unit quaternions, inverse = conjugate
        self.conjugate().normalize()
    }
    
    pub fn multiply(&self, other: &Quaternion) -> Self {
        Self {
            w: self.w * other.w - self.x * other.x - self.y * other.y - self.z * other.z,
            x: self.w * other.x + self.x * other.w + self.y * other.z - self.z * other.y,
            y: self.w * other.y - self.x * other.z + self.y * other.w + self.z * other.x,
            z: self.w * other.z + self.x * other.y - self.y * other.x + self.z * other.w,
        }
    }
    
    pub fn rotate_vector(&self, v: &Vector3) -> Vector3 {
        // q * v * q^-1 for pure quaternion v
        let pure_quat = Quaternion::new(0.0, v.x, v.y, v.z);
        let result = self.multiply(&pure_quat.multiply(&self.inverse()));
        
        Vector3::new(result.x, result.y, result.z)
    }
    
    pub fn to_euler(&self) -> EulerAngles {
        // Convert quaternion to Euler angles
        let w2 = self.w * self.w;
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        let z2 = self.z * self.z;
        
        let unit = w2 + x2 + y2 + z2;
        let test = self.w * self.x + self.y * self.z;
        
        let pitch: f64;
        let yaw: f64;
        let roll: f64;
        
        // Singularity test
        if test > 0.499 * unit {
            // Singularity at north pole
            yaw = 2.0 * self.z.atan2(self.w);
            pitch = PI / 2.0;
            roll = 0.0;
        } else if test < -0.499 * unit {
            // Singularity at south pole
            yaw = -2.0 * self.z.atan2(self.w);
            pitch = -PI / 2.0;
            roll = 0.0;
        } else {
            yaw = (2.0 * (self.w * self.z + self.x * self.y)).atan2(w2 + x2 - y2 - z2);
            pitch = ((2.0 * (self.w * self.y - self.z * self.x)) / unit).asin();
            roll = (2.0 * (self.w * self.x + self.y * self.z)).atan2(w2 - x2 - y2 + z2);
        }
        
        EulerAngles { pitch, yaw, roll }
    }
    
    pub fn slerp(&self, other: &Quaternion, t: f64) -> Quaternion {
        // Spherical linear interpolation between quaternions
        let mut dot = self.w * other.w + self.x * other.x + self.y * other.y + self.z * other.z;
        
        // If the dot product is negative, we need to invert one quaternion
        // to take the shorter path
        let mut other_adjusted = other.clone();
        if dot < 0.0 {
            other_adjusted.w = -other_adjusted.w;
            other_adjusted.x = -other_adjusted.x;
            other_adjusted.y = -other_adjusted.y;
            other_adjusted.z = -other_adjusted.z;
            dot = -dot;
        }
        
        // If the quaternions are very close, we can use linear interpolation
        if dot > 0.9995 {
            return Quaternion {
                w: self.w + t * (other_adjusted.w - self.w),
                x: self.x + t * (other_adjusted.x - self.x),
                y: self.y + t * (other_adjusted.y - self.y),
                z: self.z + t * (other_adjusted.z - self.z),
            }.normalize();
        }
        
        // Calculate the angle between the quaternions
        let theta_0 = dot.acos();
        let theta = theta_0 * t;
        
        // Calculate the interpolated quaternion
        let sin_theta = theta.sin();
        let sin_theta_0 = theta_0.sin();
        
        let s0 = ((theta_0 - theta).cos() - dot * theta.cos()) / sin_theta_0;
        let s1 = sin_theta / sin_theta_0;
        
        Quaternion {
            w: self.w * s0 + other_adjusted.w * s1,
            x: self.x * s0 + other_adjusted.x * s1,
            y: self.y * s0 + other_adjusted.y * s1,
            z: self.z * s0 + other_adjusted.z * s1,
        }.normalize()
    }
}

impl KeplerianElements {
    pub fn new(
        semi_major_axis: f64,
        eccentricity: f64,
        inclination: f64,
        longitude_ascending_node: f64,
        argument_periapsis: f64,
        mean_anomaly_epoch: f64,
        central_mass: f64,
    ) -> Self {
        // Calculate orbital period using Kepler's third law
        let orbital_period = 2.0 * PI * (semi_major_axis.powi(3) / (G * central_mass)).sqrt();
        
        Self {
            semi_major_axis,
            eccentricity,
            inclination,
            longitude_ascending_node,
            argument_periapsis,
            mean_anomaly_epoch,
            orbital_period,
            central_mass,
        }
    }
    
    pub fn calculate_position(&self, time_since_epoch: f64) -> Vector3 {
        // Calculate mean anomaly at current time
        let mean_motion = 2.0 * PI / self.orbital_period;
        let mean_anomaly = self.mean_anomaly_epoch + mean_motion * time_since_epoch;
        
        // Solve Kepler's equation for eccentric anomaly
        let eccentric_anomaly = self.solve_kepler_equation(mean_anomaly);
        
        // Calculate true anomaly
        let true_anomaly = if self.eccentricity < 1.0 {
            let factor = ((1.0 + self.eccentricity) / (1.0 - self.eccentricity)).sqrt();
            2.0 * ((eccentric_anomaly / 2.0).tan() * factor).atan()
        } else {
            // For hyperbolic orbits (e >= 1)
            2.0 * ((self.eccentricity + 1.0).sqrt() * (eccentric_anomaly / 2.0).tanh() / 
                  (self.eccentricity - 1.0).sqrt()).atan()
        };
        
        // Calculate distance from focus
        let distance = self.semi_major_axis * (1.0 - self.eccentricity * eccentric_anomaly.cos());
        
        // Position in orbital plane (2D)
        let x_orbital = distance * true_anomaly.cos();
        let y_orbital = distance * true_anomaly.sin();
        
        // Rotation matrices for orbital plane orientation
        // Calculate rotation matrix components
        let cos_i = self.inclination.cos();
        let sin_i = self.inclination.sin();
        let cos_node = self.longitude_ascending_node.cos();
        let sin_node = self.longitude_ascending_node.sin();
        let cos_arg = self.argument_periapsis.cos();
        let sin_arg = self.argument_periapsis.sin();
        
        // Transform to reference frame
        let x_ref = (cos_node * cos_arg - sin_node * sin_arg * cos_i) * x_orbital + 
                    (-cos_node * sin_arg - sin_node * cos_arg * cos_i) * y_orbital;
        let y_ref = (sin_node * cos_arg + cos_node * sin_arg * cos_i) * x_orbital + 
                    (-sin_node * sin_arg + cos_node * cos_arg * cos_i) * y_orbital;
        let z_ref = (sin_arg * sin_i) * x_orbital + (cos_arg * sin_i) * y_orbital;
        
        Vector3::new(x_ref, y_ref, z_ref)
    }
    
    fn solve_kepler_equation(&self, mean_anomaly: f64) -> f64 {
        // Normalize mean anomaly to [0, 2π)
        let normalized_ma = mean_anomaly % (2.0 * PI);
        
        // Initial guess for eccentric anomaly
        let mut eccentric_anomaly = if self.eccentricity < 0.8 {
            normalized_ma // Good initial guess for low eccentricity
        } else {
            PI // Better guess for high eccentricity
        };
        
        // Newton-Raphson method to solve Kepler's equation: M = E - e*sin(E)
        let max_iterations = 15;
        let tolerance = 1e-12;
        
        for _ in 0..max_iterations {
            let function = eccentric_anomaly - self.eccentricity * eccentric_anomaly.sin() - normalized_ma;
            let derivative = 1.0 - self.eccentricity * eccentric_anomaly.cos();
            
            let delta = function / derivative;
            eccentric_anomaly -= delta;
            
            if delta.abs() < tolerance {
                break;
            }
        }
        
        eccentric_anomaly
    }
    
    pub fn calculate_velocity(&self, time_since_epoch: f64) -> Vector3 {
        // Calculate mean anomaly at current time
        let mean_motion = 2.0 * PI / self.orbital_period;
        let mean_anomaly = self.mean_anomaly_epoch + mean_motion * time_since_epoch;
        
        // Solve Kepler's equation for eccentric anomaly
        let eccentric_anomaly = self.solve_kepler_equation(mean_anomaly);
        
        // Calculate position parameters
        let p = self.semi_major_axis * (1.0 - self.eccentricity * self.eccentricity);
        
        // Calculate velocity components in orbital plane
        let mu = G * self.central_mass;
        let factor = (mu / p).sqrt();
        
        let vx_orbital = -factor * self.eccentricity.sin();
        let vy_orbital = factor * (1.0 + self.eccentricity * eccentric_anomaly.cos());
        
        // Rotation matrices for orbital plane orientation (same as position calculation)
        let cos_i = self.inclination.cos();
        let sin_i = self.inclination.sin();
        let cos_node = self.longitude_ascending_node.cos();
        let sin_node = self.longitude_ascending_node.sin();
        let cos_arg = self.argument_periapsis.cos();
        let sin_arg = self.argument_periapsis.sin();
        
        // Transform to reference frame
        let vx_ref = (cos_node * cos_arg - sin_node * sin_arg * cos_i) * vx_orbital + 
                     (-cos_node * sin_arg - sin_node * cos_arg * cos_i) * vy_orbital;
        let vy_ref = (sin_node * cos_arg + cos_node * sin_arg * cos_i) * vx_orbital + 
                     (-sin_node * sin_arg + cos_node * cos_arg * cos_i) * vy_orbital;
        let vz_ref = (sin_arg * sin_i) * vx_orbital + (cos_arg * sin_i) * vy_orbital;
        
        Vector3::new(vx_ref, vy_ref, vz_ref)
    }
}

impl AABB {
    pub fn new(min: Vector3, max: Vector3) -> Self {
        Self { min, max }
    }
    
    pub fn from_points(points: &[Vector3]) -> Self {
        if points.is_empty() {
            return Self {
                min: Vector3::zero(),
                max: Vector3::zero(),
            };
        }
        
        let mut min = points[0].clone();
        let mut max = points[0].clone();
        
        for point in points.iter().skip(1) {
            min.x = min.x.min(point.x);
            min.y = min.y.min(point.y);
            min.z = min.z.min(point.z);
            
            max.x = max.x.max(point.x);
            max.y = max.y.max(point.y);
            max.z = max.z.max(point.z);
        }
        
        Self { min, max }
    }
    
    pub fn contains_point(&self, point: &Vector3) -> bool {
        point.x >= self.min.x && point.x <= self.max.x &&
        point.y >= self.min.y && point.y <= self.max.y &&
        point.z >= self.min.z && point.z <= self.max.z
    }
    
    pub fn intersects(&self, other: &AABB) -> bool {
        self.min.x <= other.max.x && self.max.x >= other.min.x &&
        self.min.y <= other.max.y && self.max.y >= other.min.y &&
        self.min.z <= other.max.z && self.max.z >= other.min.z
    }
    
    pub fn merge(&self, other: &AABB) -> AABB {
        AABB {
            min: Vector3::new(
                self.min.x.min(other.min.x),
                self.min.y.min(other.min.y),
                self.min.z.min(other.min.z),
            ),
            max: Vector3::new(
                self.max.x.max(other.max.x),
                self.max.y.max(other.max.y),
                self.max.z.max(other.max.z),
            ),
        }
    }
    
    pub fn size(&self) -> Vector3 {
        Vector3::new(
            self.max.x - self.min.x,
            self.max.y - self.min.y,
            self.max.z - self.min.z,
        )
    }
    
    pub fn center(&self) -> Vector3 {
        Vector3::new(
            (self.min.x + self.max.x) / 2.0,
            (self.min.y + self.max.y) / 2.0,
            (self.min.z + self.max.z) / 2.0,
        )
    }
    
    pub fn volume(&self) -> f64 {
        let size = self.size();
        size.x * size.y * size.z
    }
    
    pub fn ray_intersection(&self, origin: &Vector3, direction: &Vector3) -> Option<(f64, f64)> {
        // Returns entry and exit distances if ray intersects AABB
        let inv_dir = Vector3::new(
            1.0 / direction.x,
            1.0 / direction.y,
            1.0 / direction.z,
        );
        
        let t1 = (self.min.x - origin.x) * inv_dir.x;
        let t2 = (self.max.x - origin.x) * inv_dir.x;
        let t3 = (self.min.y - origin.y) * inv_dir.y;
        let t4 = (self.max.y - origin.y) * inv_dir.y;
        let t5 = (self.min.z - origin.z) * inv_dir.z;
        let t6 = (self.max.z - origin.z) * inv_dir.z;
        
        let tmin = t1.min(t2).max(t3.min(t4)).max(t5.min(t6));
        let tmax = t1.max(t2).min(t3.max(t4)).min(t5.max(t6));
        
        // Ray (line) intersects AABB, but the box is behind us
        if tmax < 0.0 {
            return None;
        }
        
        // Ray doesn't intersect AABB
        if tmin > tmax {
            return None;
        }
        
        Some((tmin, tmax))
    }
}

impl OctreeNode {
    pub fn new(center: Vector3, half_dimension: f64, depth: u32) -> Self {
        let min = Vector3::new(
            center.x - half_dimension,
            center.y - half_dimension,
            center.z - half_dimension,
        );
        let max = Vector3::new(
            center.x + half_dimension,
            center.y + half_dimension,
            center.z + half_dimension,
        );
        
        Self {
            aabb: AABB::new(min, max),
            center,
            half_dimension,
            entities: Vec::new(),
            children: None,
            depth,
        }
    }
    
    pub fn insert(
        &mut self,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>,
        entity_id: u32,
        entity_type: EntityType,
        position: &Vector3,
        max_depth: u32,
        max_entities: usize
    ) {
        if !self.aabb.contains_point(position) {
            return;
        }
        
        // If we're at max depth or under the entity threshold, add to this node
        if self.depth >= max_depth || self.entities.len() < max_entities {
            self.entities.push((entity_id, entity_type));
            return;
        }
        
        // Otherwise, subdivide if necessary and insert into child nodes
        if self.children.is_none() {
            self.subdivide(containers, pois, poi_states);
        }
        
        if let Some(ref mut children) = self.children {
            for child in children.iter_mut() {
                if child.aabb.contains_point(position) {
                    child.insert(containers, pois, poi_states, entity_id, entity_type, position, max_depth, max_entities);
                    return;
                }
            }
        }
        
        // If we couldn't insert into a child (shouldn't happen), add to this node
        self.entities.push((entity_id, entity_type));
    }
    
    pub fn subdivide(
        &mut self, 
        containers: &HashMap<u32, ObjectContainer>, 
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) {
        let half = self.half_dimension / 2.0;
        let depth = self.depth + 1;
        
        // Create 8 children for the octants
        let mut children = Box::new([
            // Bottom four quadrants (z - half)
            OctreeNode::new(
                Vector3::new(self.center.x - half, self.center.y - half, self.center.z - half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x + half, self.center.y - half, self.center.z - half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x - half, self.center.y + half, self.center.z - half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x + half, self.center.y + half, self.center.z - half),
                half, depth
            ),
            // Top four quadrants (z + half)
            OctreeNode::new(
                Vector3::new(self.center.x - half, self.center.y - half, self.center.z + half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x + half, self.center.y - half, self.center.z + half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x - half, self.center.y + half, self.center.z + half),
                half, depth
            ),
            OctreeNode::new(
                Vector3::new(self.center.x + half, self.center.y + half, self.center.z + half),
                half, depth
            ),
        ]);
        
        // Move existing entities to appropriate children
        let entities = std::mem::replace(&mut self.entities, Vec::new());
    
        for (entity_id, entity_type) in entities {
            let position = resolve_entity_position(containers, pois, poi_states, entity_id, entity_type);
            
            if let Some(pos) = position {
                let mut inserted = false;
                for child in children.iter_mut() {
                    if child.aabb.contains_point(&pos) {
                        child.insert(containers, pois, poi_states, entity_id, entity_type, &pos, self.depth + 3, 8);
                        inserted = true;
                        break;
                    }
                }
                if !inserted {
                    self.entities.push((entity_id, entity_type));
                }
            } else {
                self.entities.push((entity_id, entity_type));
            }
        }
        
        self.children = Some(children);
    }
    
    pub fn query_radius(
        &self,
        center: &Vector3,
        radius: f64,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) -> Vec<(u32, EntityType)> {
        let mut result = Vec::new();
        
        // Check if query sphere intersects this node
        let closest_point = Vector3::new(
            center.x.max(self.aabb.min.x).min(self.aabb.max.x),
            center.y.max(self.aabb.min.y).min(self.aabb.max.y),
            center.z.max(self.aabb.min.z).min(self.aabb.max.z),
        );
        
        if closest_point.distance(center) > radius {
            return result;
        }
        
        // Add entities from this node
        for &(entity_id, entity_type) in &self.entities {
            if let Some(position) = resolve_entity_position(
                containers, pois, poi_states, entity_id, entity_type
            ) {
                if position.distance(center) <= radius {
                    result.push((entity_id, entity_type));
                }
            }
        }
        
        // Recursively query children
        if let Some(ref children) = self.children {
            for child in children.iter() {
                result.extend(child.query_radius(center, radius, containers, pois, poi_states));
            }
        }
        
        result
    }
    
    pub fn get_all_entities(&self) -> Vec<(u32, EntityType)> {
        let mut result = self.entities.clone();
        
        if let Some(ref children) = self.children {
            for child in children.iter() {
                result.extend(child.get_all_entities());
            }
        }
        
        result
    }
    
    pub fn update_entity(
        &mut self,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>,
        entity_id: u32,
        entity_type: EntityType,
        new_position: &Vector3,
        max_depth: u32,
        max_entities: usize,
    ) -> bool {
        // Check if entity exists in this node
        let entity_index = self.entities.iter().position(|&(id, ty)| id == entity_id && ty == entity_type);

        if let Some(index) = entity_index {
            let entity = self.entities.remove(index);
            // Re-insert at its new position
            self.insert(containers, pois, poi_states, entity.0, entity.1, new_position, max_depth, max_entities);
            return true;
        }
        
        // Check children
        if let Some(ref mut children) = self.children {
            for child in children.iter_mut() {
                if child.update_entity(containers, pois, poi_states, entity_id, entity_type, new_position, max_depth, max_entities) {
                    return true;
                }
            }
        }
        
        false
    }
}

impl BVHNode {
    pub fn new(entities: Vec<(u32, EntityType)>, system: &InterstellarNavigationSystem) -> Self {
        let positions: Vec<Vector3> = entities.iter()
            .filter_map(|&(id, ty)| system.get_entity_position(id, ty))
            .collect();
        
        let aabb = if positions.is_empty() {
            AABB::new(Vector3::zero(), Vector3::zero())
        } else {
            AABB::from_points(&positions)
        };
        
        Self {
            aabb,
            entities,
            left: None,
            right: None,
        }
    }
    
    pub fn build(
        &mut self,
        max_entities_per_node: usize,
        system: &InterstellarNavigationSystem,
    ) {
        if self.entities.len() <= max_entities_per_node {
            return;
        }
        
        // Find the axis with the greatest extent
        let size = self.aabb.size();
        let axis = if size.x > size.y && size.x > size.z {
            0 // x-axis
        } else if size.y > size.z {
            1 // y-axis
        } else {
            2 // z-axis
        };
        
        // Get positions for sorting
        let mut entity_positions: Vec<((u32, EntityType), Option<Vector3>)> = self.entities.iter()
            .map(|&(id, ty)| ((id, ty), system.get_entity_position(id, ty)))
            .collect();
        
        // Filter out entities without positions
        entity_positions.retain(|(_, pos)| pos.is_some());
        
        // Sort entities along the chosen axis
        entity_positions.sort_by(|a, b| {
            let val_a = match axis {
                0 => a.1.as_ref().map(|v| v.x),
                1 => a.1.as_ref().map(|v| v.y),
                _ => a.1.as_ref().map(|v| v.z),
            };
            
            let val_b = match axis {
                0 => b.1.as_ref().map(|v| v.x),
                1 => b.1.as_ref().map(|v| v.y),
                _ => b.1.as_ref().map(|v| v.z),
            };
            
            match (val_a, val_b) {
                (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        });
        
        // Split into left and right groups
        let mid = entity_positions.len() / 2;
        let left_entities: Vec<(u32, EntityType)> = entity_positions[0..mid].iter()
            .map(|&((id, ty), _)| (id, ty))
            .collect();
        let right_entities: Vec<(u32, EntityType)> = entity_positions[mid..].iter()
            .map(|&((id, ty), _)| (id, ty))
            .collect();
        
        // Clear the current node's entities to prevent duplication
        self.entities.clear();
        
        // Create children
        if !left_entities.is_empty() {
            let mut left_node = BVHNode::new(left_entities, system);
            left_node.build(max_entities_per_node, system);
            self.left = Some(Box::new(left_node));
        }
        
        if !right_entities.is_empty() {
            let mut right_node = BVHNode::new(right_entities, system);
            right_node.build(max_entities_per_node, system);
            self.right = Some(Box::new(right_node));
        }
    }
    
    pub fn query_radius(
        &self,
        center: &Vector3,
        radius: f64,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) -> Vec<(u32, EntityType)> {
        let mut result = Vec::new();
        
        // Check if sphere overlaps this node's AABB
        let closest_point = Vector3::new(
            center.x.max(self.aabb.min.x).min(self.aabb.max.x),
            center.y.max(self.aabb.min.y).min(self.aabb.max.y),
            center.z.max(self.aabb.min.z).min(self.aabb.max.z),
        );
        
        if closest_point.distance(center) > radius {
            return result;
        }
        
        // Add entities from this node
        for &(entity_id, entity_type) in &self.entities {
            if let Some(position) = resolve_entity_position(
                containers, pois, poi_states, entity_id, entity_type
            ) {
                if position.distance(center) <= radius {
                    result.push((entity_id, entity_type));
                }
            }
        }
        
        // Query children
        if let Some(ref left) = self.left {
            result.extend(left.query_radius(center, radius, containers, pois, poi_states));
        }
        
        if let Some(ref right) = self.right {
            result.extend(right.query_radius(center, radius, containers, pois, poi_states));
        }
        
        result
    }
    
    pub fn ray_intersection(
        &self,
        origin: &Vector3,
        direction: &Vector3,
        max_distance: f64,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) -> Vec<((u32, EntityType), f64)> {
        let mut result = Vec::new();
        
        // Check if ray intersects this node's AABB
        if let Some((t_min, t_max)) = self.aabb.ray_intersection(origin, direction) {
            if t_min > max_distance || t_max < 0.0 {
                return result;
            }
            
            // Check entities in this node
            for &(entity_id, entity_type) in &self.entities {
                let position_opt = resolve_entity_position(containers, pois, poi_states, entity_id, entity_type);
                
                let (position, radius) = match (position_opt, entity_type) {
                    (Some(pos), EntityType::ObjectContainer) => {
                        if let Some(container) = containers.get(&entity_id) {
                            (pos, container.body_radius)
                        } else {
                            continue;
                        }
                    },
                    (Some(pos), EntityType::PointOfInterest) => {
                        (pos, 0.0) // No collision radius for POIs
                    },
                    _ => continue,
                };
                
                // Simple sphere-ray intersection
                if radius > 0.0 {
                    let oc = position.sub(origin);
                    let tca = oc.dot(direction);
                    
                    if tca < 0.0 {
                        continue; // Behind the ray origin
                    }
                    
                    let d2 = oc.dot(&oc) - tca * tca;
                    let r2 = radius * radius;
                    
                    if d2 > r2 {
                        continue; // Ray misses the sphere
                    }
                    
                    let thc = (r2 - d2).sqrt();
                    let t0 = tca - thc;
                    
                    if t0 < max_distance {
                        result.push(((entity_id, entity_type), t0));
                    }
                }
            }
            
            // Check children
            if let Some(ref left) = self.left {
                result.extend(left.ray_intersection(origin, direction, max_distance, containers, pois, poi_states));
            }
            
            if let Some(ref right) = self.right {
                result.extend(right.ray_intersection(origin, direction, max_distance, containers, pois, poi_states));
            }
        }
        
        result
    }
}

impl HybridSpatialIndex {
    pub fn new(system_size: f64) -> Self {
        let center = Vector3::zero(); // Star at the origin
        let half_dimension = system_size / 2.0;
        
        Self {
            octree_root: OctreeNode::new(center, half_dimension, 0),
            bvh_regions: Vec::new(),
            entity_positions: HashMap::new(),
        }
    }
    
    pub fn insert(
        &mut self,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>,
        entity_id: u32,
        entity_type: EntityType,
        position: &Vector3
    ) {
        // Cache the position
        self.entity_positions.insert((entity_id, entity_type), position.clone());
        
        // Check if there's a high-density region that would benefit from BVH
        // For now, we'll just insert into the octree
        self.octree_root.insert(containers, pois, poi_states, entity_id, entity_type, position, 8, 10); // Max depth 8, max 10 entities per node
    }
    
    pub fn update_entity_position(
        &mut self,
        entity_id: u32,
        entity_type: EntityType,
        new_position: &Vector3,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) {
        // Update the entity in the main octree
        self.octree_root.update_entity(containers, pois, poi_states, entity_id, entity_type, new_position, 8, 10);
        
        // Update the position cache
        self.entity_positions.insert((entity_id, entity_type), new_position.clone());
    }
    
    pub fn query_radius(
        &self,
        center: &Vector3,
        radius: f64,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) -> Vec<(u32, EntityType)> {
        let mut result = self.octree_root.query_radius(center, radius, containers, pois, poi_states);
        
        // Also query BVH regions
        for bvh in &self.bvh_regions {
            let bvh_results = bvh.query_radius(center, radius, containers, pois, poi_states);
            result.extend(bvh_results);
        }
        
        // Remove duplicates
        let mut unique = HashSet::new();
        result.retain(|&(id, ty)| unique.insert((id, ty)));
        
        result
    }
    
    pub fn ray_cast(
        &self,
        origin: &Vector3,
        direction: &Vector3,
        max_distance: f64,
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) -> Vec<((u32, EntityType), f64)> {
        let mut results = Vec::new();
        
        // Cast ray through octree entities
        let all_entities = self.octree_root.get_all_entities();
        
        for (entity_id, entity_type) in all_entities {
            let position_opt = resolve_entity_position(containers, pois, poi_states, entity_id, entity_type);
            
            let (position, radius) = match (position_opt, entity_type) {
                (Some(pos), EntityType::ObjectContainer) => {
                    if let Some(container) = containers.get(&entity_id) {
                        (pos, container.body_radius)
                    } else {
                        continue;
                    }
                },
                (Some(pos), EntityType::PointOfInterest) => {
                    (pos, 0.0) // No collision radius for POIs
                },
                _ => continue,
            };
            
            if radius > 0.0 {
                // Sphere-ray intersection test
                let oc = position.sub(origin);
                let tca = oc.dot(direction);
                
                if tca < 0.0 {
                    continue; // Behind the ray
                }
                
                let d2 = oc.dot(&oc) - tca * tca;
                let r2 = radius * radius;
                
                if d2 > r2 {
                    continue; // Ray misses the sphere
                }
                
                let thc = (r2 - d2).sqrt();
                let t0 = tca - thc; // Entry distance
                
                if t0 < max_distance {
                    results.push(((entity_id, entity_type), t0));
                }
            }
        }
        
        // Also cast through BVH regions
        for bvh in &self.bvh_regions {
            let bvh_results = bvh.ray_intersection(origin, direction, max_distance, containers, pois, poi_states);
            results.extend(bvh_results);
        }
        
        // Sort by distance and remove duplicates
        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
        
        let mut unique = HashSet::new();
        results.retain(|&((id, ty), _)| unique.insert((id, ty)));
        
        results
    }
    
    pub fn rebuild(
        &mut self, 
        system_size: f64, 
        containers: &HashMap<u32, ObjectContainer>,
        pois: &HashMap<u32, PointOfInterest>,
        poi_states: &HashMap<u32, PoiState>
    ) {
        let center = Vector3::zero(); // Star at the origin
        let half_dimension = system_size / 2.0;
        
        self.octree_root = OctreeNode::new(center, half_dimension, 0);
        self.bvh_regions.clear();
        self.entity_positions.clear();
        
        // Add all containers
        for (id, container) in containers {
            self.insert(
                containers,
                pois,
                poi_states,
                *id,
                EntityType::ObjectContainer,
                &container.position,
            );
        }
        
        // Add all POIs
        for (id, poi) in pois {
            if let Some(position) = resolve_entity_position(containers, pois, poi_states, *id, EntityType::PointOfInterest) {
                self.insert(
                    containers,
                    pois,
                    poi_states,
                    *id,
                    EntityType::PointOfInterest,
                    &position,
                );
            }
        }
    }
}

impl InterstellarNavigationSystem {
    pub fn new() -> Self {
        let system_size = 1_000_000_000_000.0; // 1,000,000,000 km (interplanetary scale)
        let spatial_index = HybridSpatialIndex::new(system_size);
        
        let origin_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        Self {
            containers: HashMap::new(),
            pois: HashMap::new(),
            orbital_markers: HashMap::new(),
            container_states: HashMap::new(),
            poi_states: HashMap::new(),
            spatial_index,
            current_time: 0.0, // Start at t=0
            origin_time, // Jan 1, 2020 reference time
            last_position_update: 0.0,
            last_index_update: 0.0,
            last_path_update: HashMap::new(),
            active_paths: HashMap::new(),
            default_constraints: NavigationConstraints {
                min_approach_distance: 10_000.0, // 10 km
                prefer_distance: true,
                prefer_segments: false,
                prefer_safety: false,
                buffer_distance: 50_000.0, // 50 km
                max_hydrogen_distance: 100_000.0, // 100 km
                avoid_atmospheres: true,
                min_altitude: 5_000.0, // 5 km above atmosphere
                safety_margin: 20_000.0, // 20 km safety margin
            },
        }
    }
    
    pub fn load_containers(&mut self, containers: Vec<ObjectContainer>) {
        for container in containers {
            let id = container.id;
            
            // Calculate derived properties
            let atmosphere_radius = match container.container_type {
                ContainerType::Planet => container.body_radius + 10_000.0, // 10 km atmosphere by default
                _ => container.body_radius,
            };
            
            let safety_radius = match container.container_type {
                ContainerType::Planet => atmosphere_radius,
                _ => container.body_radius + 10_000.0, // 10 km safety margin for airless bodies
            };
            
            // Calculate approximate mass based on radius and type
            let density = match container.container_type {
                ContainerType::Star => 1410.0,  // Solar density kg/m³
                ContainerType::Planet => 5515.0, // Earth density kg/m³
                ContainerType::Moon => 3340.0,  // Lunar density kg/m³
                _ => 3000.0,                    // Default density
            };
            
            let mass = (4.0/3.0) * PI * container.body_radius.powi(3) * density;
            
            // Store container in collection
            self.containers.insert(id, container);
            
            // Create container state
            let state = ContainerState {
                atmosphere_radius,
                safety_radius,
                parent_id: None, // Will be established later
                orbital_markers: Vec::new(),
                mass,
                orbital_elements: None, // Will be established later
                creation_time: self.current_time,
                last_update_time: self.current_time,
            };
            
            self.container_states.insert(id, state);
            
            // Add to spatial index using correct position
            if let Some(position) = self.get_entity_position(id, EntityType::ObjectContainer) {
                self.spatial_index.insert(
                    &self.containers, 
                    &self.pois, 
                    &self.poi_states,
                    id, 
                    EntityType::ObjectContainer, 
                    &position
                );
            }
        }
        
        // Establish parent-child relationships and orbital elements
        self.establish_container_hierarchy();
        
        // Generate orbital markers for all containers
        self.generate_all_orbital_markers();
    }
    
    pub fn load_pois(&mut self, pois: Vec<PointOfInterest>) {
        for poi in pois {
            let id = poi.id;
            
            // Determine parent and motion type
            let (parent_id, motion_type) = if let Some(ref container_name) = poi.obj_container {
                // Find container by name
                let mut parent = None;
                let mut motion = MotionType::Static;
                
                for (container_id, container) in &self.containers {
                    if &container.name == container_name {
                        parent = Some(*container_id);
                        
                        // Infer motion type based on position and container type
                        if container.container_type == ContainerType::Planet || 
                           container.container_type == ContainerType::Moon {
                            
                            // Calculate distance from container center
                            let distance = poi.position.magnitude();

                            // If significantly above surface, assume orbiting
                            if distance > container.body_radius * 1.2 {
                                motion = MotionType::Orbiting;
                            }
                        }
                        
                        break;
                    }
                }
                
                (parent, motion)
            } else {
                (None, MotionType::Static)
            };
            
            // Calculate local position if parent exists
            let local_position = if let Some(parent_id) = parent_id {
                if let Some(parent) = self.containers.get(&parent_id) {
                    // Inverse transform to get local position
                    let global_pos = poi.position.clone();
                    let parent_pos = parent.position.clone();
                    let relative_pos = global_pos.sub(&parent_pos);
                    
                    // Inverse rotate
                    parent.rot_quat.inverse().rotate_vector(&relative_pos)
                } else {
                    Vector3::zero()
                }
            } else {
                Vector3::zero()
            };
            
            // Store POI in collection
            self.pois.insert(id, poi);
            
            // Create POI state
            let state = PoiState {
                local_position,
                parent_id,
                motion_type,
                independent_motion: None, // Could be set separately if needed
                last_update_time: self.current_time,
            };
            
            self.poi_states.insert(id, state);
            
            // Add to spatial index using resolved position
            if let Some(position) = self.get_entity_position(id, EntityType::PointOfInterest) {
                self.spatial_index.insert(
                    &self.containers, 
                    &self.pois, 
                    &self.poi_states,
                    id, 
                    EntityType::PointOfInterest, 
                    &position
                );
            }
        }
    }
    
    pub fn generate_all_orbital_markers(&mut self) {
        for id in self.containers.keys().copied().collect::<Vec<_>>() {
            self.generate_orbital_markers(id);
        }
    }
    
    pub fn generate_orbital_markers(&mut self, container_id: u32) {
        if let Some(container) = self.containers.get(&container_id) {
            let om_count = 6; // Default number of OMs
            let om_radius = container.om_radius;
            
            // Generate orbital markers evenly around the equator
            for i in 0..om_count {
                let angle = 2.0 * PI * (i as f64) / (om_count as f64);
                let local_pos = Vector3::new(
                    om_radius * angle.cos(),
                    om_radius * angle.sin(),
                    0.0, // On the equatorial plane
                );
                
                // Transform to global position
                let global_pos = self.transform_local_to_global(&local_pos, container_id);
                
                let marker_id = (container_id * 100) + i as u32; // Unique ID scheme
                
                let marker = OrbitalMarker {
                    id: marker_id,
                    name: format!("{}-OM-{}", container.name, i + 1),
                    container_id,
                    local_position: local_pos,
                    global_position: global_pos,
                };
                
                // Store marker in collection
                self.orbital_markers.insert(marker_id, marker);
                
                // Update container state to reference this marker
                if let Some(state) = self.container_states.get_mut(&container_id) {
                    state.orbital_markers.push(marker_id);
                }
            }
        }
    }
    
    pub fn establish_container_hierarchy(&mut self) {
        // Identify potential moons based on ContainerType
        let moon_ids: Vec<u32> = self.containers.iter()
            .filter(|(_, container)| container.container_type == ContainerType::Moon)
            .map(|(id, _)| *id)
            .collect();
        
        // Create temporary storage for hierarchy updates to avoid borrowing conflicts
        let mut updates: Vec<(u32, Option<u32>, Option<KeplerianElements>)> = Vec::new();
        
        // For each moon, find the most probable parent planet
        for moon_id in moon_ids {
            if let Some(moon) = self.containers.get(&moon_id) {
                let moon_position = moon.position.clone();
                
                // Find closest planet that could be the parent
                let mut parent_id = None;
                let mut min_score = f64::MAX;
                
                for (id, container) in &self.containers {
                    // Skip if not a planet or star
                    if container.container_type != ContainerType::Planet && 
                       container.container_type != ContainerType::Star {
                        continue;
                    }
                    
                    // Skip if this is the moon itself
                    if *id == moon_id {
                        continue;
                    }
                    
                    // Calculate distance
                    let distance = container.position.distance(&moon_position);
                    
                    // Get container's mass from state
                    let mass = if let Some(state) = self.container_states.get(id) {
                        state.mass
                    } else {
                        0.0 // Default value instead of continue
                    };
                    
                    // Calculate Hill sphere radius (approximation)
                    let hill_radius = distance * (mass / (3.0 * 1.989e30)).powf(1.0/3.0);
                    
                    // Calculate score (lower is better)
                    let score = distance / hill_radius;
                    
                    if score < min_score && distance < hill_radius {
                        min_score = score;
                        parent_id = Some(*id);
                    }
                }
                
                // If parent found, prepare orbital elements
                if let Some(parent_id) = parent_id {
                    if let Some(parent) = self.containers.get(&parent_id) {
                        // Extract parent mass
                        let parent_mass = if let Some(parent_state) = self.container_states.get(&parent_id) {
                            parent_state.mass
                        } else {
                            0.0 // Default value
                        };
                        
                        // Calculate orbital elements
                        let relative_pos = moon.position.sub(&parent.position);
                        let distance = relative_pos.magnitude();
                        
                        // Simple orbital elements (circular orbit)
                        let semi_major_axis = distance;
                        let eccentricity = 0.0; // Circular
                        let inclination = 0.0; // Assume equatorial for simplicity
                        let longitude_ascending_node = 0.0; // Arbitrary for equatorial orbit
                        let argument_periapsis = 0.0; // Arbitrary for circular orbit
                        
                        // Calculate current position in orbit (mean anomaly)
                        let mean_anomaly_epoch = if relative_pos.x == 0.0 {
                            if relative_pos.y > 0.0 { PI / 2.0 } else { 3.0 * PI / 2.0 }
                        } else {
                            relative_pos.y.atan2(relative_pos.x)
                        };
                        
                        // Create Keplerian elements
                        let elements = KeplerianElements::new(
                            semi_major_axis,
                            eccentricity,
                            inclination,
                            longitude_ascending_node,
                            argument_periapsis,
                            mean_anomaly_epoch,
                            parent_mass,
                        );
                        
                        // Store update for later application
                        updates.push((moon_id, Some(parent_id), Some(elements)));
                    }
                }
            }
        }
        
        // Apply all updates at once to avoid borrowing conflicts
        for (moon_id, parent_id, elements) in updates {
            if let Some(moon_state) = self.container_states.get_mut(&moon_id) {
                moon_state.parent_id = parent_id;
                moon_state.orbital_elements = elements;
            }
        }
    }
    
    pub fn update_time(&mut self, new_time: f64) {
        // We'll use delta_time in calculation, so the warning is unnecessary
        let _delta_time = new_time - self.current_time;
        self.current_time = new_time;
        
        // Update positions if 1 second has passed
        if new_time - self.last_position_update >= 1.0 {
            self.update_positions();
            self.last_position_update = new_time;
        }
        
        // Update paths if needed
        let paths_to_update: Vec<u32> = self.active_paths.keys()
            .filter(|&id| {
                self.last_path_update.get(id).map_or(true, |&last_time| {
                    new_time - last_time >= 1.0
                })
            })
            .copied()
            .collect();
        
        for path_id in paths_to_update {
            if let Some(path) = self.active_paths.get(&path_id).cloned() {
                self.update_path(path_id, path);
                self.last_path_update.insert(path_id, new_time);
            }
        }
        
        // Full spatial index rebuild if necessary (significant changes or time elapsed)
        if new_time - self.last_index_update >= 60.0 {
            self.rebuild_spatial_index();
            self.last_index_update = new_time;
        }
    }
    
    pub fn transform_local_to_global(&self, local_pos: &Vector3, container_id: u32) -> Vector3 {
        if let Some(container) = self.containers.get(&container_id) {
            // Apply rotation (quaternion-based)
            let rotated = container.rot_quat.rotate_vector(local_pos);
            
            // Translate by container position
            rotated.add(&container.position)
        } else {
            local_pos.clone() // Fallback
        }
    }
    
    pub fn update_positions(&mut self) {
        // Update container positions first (parents before children)
        for container_id in self.containers.keys().copied().collect::<Vec<_>>() {
            self.update_container_position(container_id);
        }
        
        // Update POI positions second (which may depend on updated container positions)
        for poi_id in self.pois.keys().copied().collect::<Vec<_>>() {
            self.update_poi_position(poi_id);
        }
        
        // Update orbital marker positions last
        for marker_id in self.orbital_markers.keys().copied().collect::<Vec<_>>() {
            self.update_orbital_marker_position(marker_id);
        }
        
        // Update spatial indices with new properly transformed positions
        self.update_spatial_index();
    }
    
    fn update_container_position(&mut self, container_id: u32) {
        // Clone container and state to avoid borrowing conflicts
        let position_update = {
            if let (Some(container), Some(state)) = (
                self.containers.get(&container_id),
                self.container_states.get(&container_id)
            ) {
                // Compute position update if orbital elements exist
                if let (Some(elements), Some(parent_id)) = (&state.orbital_elements, state.parent_id) {
                    if let Some(parent) = self.containers.get(&parent_id) {
                        // Calculate position relative to parent using Keplerian elements
                        let time_since_epoch = self.current_time - state.creation_time;
                        let relative_position = elements.calculate_position(time_since_epoch);
                        
                        // Return global position update
                        Some((parent.position.add(&relative_position), container.rot_vel.clone()))
                    } else {
                        None
                    }
                } else {
                    // No orbital elements, just keep current position
                    Some((container.position.clone(), container.rot_vel.clone()))
                }
            } else {
                None
            }
        };
        
        // Apply the position update if calculated
        if let Some((new_position, rot_vel)) = position_update {
            if let Some(container) = self.containers.get_mut(&container_id) {
                container.position = new_position;
                
                // Update rotation quaternion based on angular velocities
                let dt = 1.0; // 1 second update
                
                // Calculate incremental rotation quaternion
                let rot_magnitude = rot_vel.magnitude();
                
                if rot_magnitude > EPSILON {
                    let axis = Vector3::new(
                        rot_vel.x / rot_magnitude,
                        rot_vel.y / rot_magnitude,
                        rot_vel.z / rot_magnitude,
                    );
                    
                    let delta_angle = rot_magnitude * dt;
                    let q_increment = Quaternion::from_axis_angle(&axis, delta_angle);
                    
                    // Apply rotation increment
                    container.rot_quat = q_increment.multiply(&container.rot_quat).normalize();
                }
            }
            
            // Update state
            if let Some(state) = self.container_states.get_mut(&container_id) {
                state.last_update_time = self.current_time;
            }
            
            // Update spatial index
            if let Some(container) = self.containers.get(&container_id) {
                self.spatial_index.update_entity_position(
                    container_id,
                    EntityType::ObjectContainer,
                    &container.position,
                    &self.containers,
                    &self.pois,
                    &self.poi_states
                );
            }
        }
    }
    
    fn update_poi_position(&mut self, poi_id: u32) {
        // This method is critical for maintaining position consistency
        // Clone the necessary data first to avoid double borrow
        let position_update = if let (Some(poi), Some(state)) = (
            self.pois.get(&poi_id),
            self.poi_states.get_mut(&poi_id)
        ) {
            let position_update = match state.motion_type {
                MotionType::Static => {
                    // POI fixed to parent's surface - update global position based on parent rotation
                    if let Some(parent_id) = state.parent_id {
                        if let Some(parent) = self.containers.get(&parent_id) {
                            // Transform local position to global
                            let rotated = parent.rot_quat.rotate_vector(&state.local_position);
                            Some(parent.position.add(&rotated))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                MotionType::Orbiting => {
                    // POI orbiting parent - compute orbital position
                    if let Some(parent_id) = state.parent_id {
                        if let Some(parent) = self.containers.get(&parent_id) {
                            // Get parent mass
                            let parent_mass = match self.container_states.get(&parent_id) {
                                Some(parent_state) => parent_state.mass,
                                None => 0.0 // Default value
                            };
                            
                            // Simplified orbit calculation
                            let orbit_radius = state.local_position.magnitude();
                            let orbit_speed = (G * parent_mass / orbit_radius.powi(3)).sqrt();
                            
                            // Calculate time delta
                            let dt = self.current_time - state.last_update_time;
                            
                            // Orbit around parent's z-axis
                            let current_angle = state.local_position.x.atan2(state.local_position.y);
                            let new_angle = current_angle + orbit_speed * dt;
                            
                            // Update local position
                            state.local_position = Vector3::new(
                                orbit_radius * new_angle.sin(),
                                orbit_radius * new_angle.cos(),
                                state.local_position.z,
                            );
                            
                            // Transform to global position
                            let rotated = parent.rot_quat.rotate_vector(&state.local_position);
                            Some(parent.position.add(&rotated))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                MotionType::Independent => {
                    // Handle independent motion via state
                    if let Some(motion) = &mut state.independent_motion {
                        // Calculate time delta
                        let dt = self.current_time - state.last_update_time;
                        
                        let new_pos = match motion {
                            IndependentMotionType::Linear { velocity, acceleration } => {
                                // Apply acceleration to velocity
                                *velocity = Vector3::new(
                                    velocity.x + acceleration.x * dt,
                                    velocity.y + acceleration.y * dt,
                                    velocity.z + acceleration.z * dt
                                );
                                
                                // Apply velocity to position
                                Some(Vector3::new(
                                    poi.position.x + velocity.x * dt + 0.5 * acceleration.x * dt * dt,
                                    poi.position.y + velocity.y * dt + 0.5 * acceleration.y * dt * dt,
                                    poi.position.z + velocity.z * dt + 0.5 * acceleration.z * dt * dt
                                ))
                            },
                            IndependentMotionType::Circular { center, axis, angular_velocity, radius } => {
                                // Create a rotation quaternion for the angular movement
                                let rotation_angle = *angular_velocity * dt;
                                let rotation_quat = Quaternion::from_axis_angle(axis, rotation_angle);
                                
                                // Calculate vector from center to POI
                                let current_relative_pos = Vector3::new(
                                    poi.position.x - center.x,
                                    poi.position.y - center.y,
                                    poi.position.z - center.z
                                );
                                
                                // Rotate the current position around the center
                                let rotated_pos = rotation_quat.rotate_vector(&current_relative_pos);
                                
                                // Ensure the object stays at the specified radius
                                let actual_radius = rotated_pos.magnitude();
                                let correction_factor = if actual_radius > EPSILON {
                                    *radius / actual_radius
                                } else {
                                    1.0
                                };
                                
                                Some(Vector3::new(
                                    center.x + rotated_pos.x * correction_factor,
                                    center.y + rotated_pos.y * correction_factor,
                                    center.z + rotated_pos.z * correction_factor
                                ))
                            },
                            IndependentMotionType::Programmed { waypoints, current_index, loop_motion } => {
                                if waypoints.len() < 2 {
                                    Some(poi.position.clone())
                                } else {
                                    let simulation_time = self.current_time;
                                    
                                    while *current_index < waypoints.len() - 1 && 
                                          waypoints[*current_index + 1].1 < simulation_time {
                                        *current_index += 1;
                                    }
                                    
                                    if *current_index >= waypoints.len() - 1 {
                                        if *loop_motion {
                                            *current_index = 0;
                                            Some(waypoints[0].0.clone())
                                        } else {
                                            Some(waypoints.last().unwrap().0.clone())
                                        }
                                    } else {
                                        let t1 = waypoints[*current_index].1;
                                        let t2 = waypoints[*current_index + 1].1;
                                        let p1 = &waypoints[*current_index].0;
                                        let p2 = &waypoints[*current_index + 1].0;
                                        
                                        let t_factor = if t2 == t1 { 0.0 } else { (simulation_time - t1) / (t2 - t1) };
                                        let clamped_t = t_factor.clamp(0.0, 1.0);
                                        
                                        Some(Vector3::new(
                                            p1.x + (p2.x - p1.x) * clamped_t,
                                            p1.y + (p2.y - p1.y) * clamped_t,
                                            p1.z + (p2.z - p1.z) * clamped_t
                                        ))
                                    }
                                }
                            },
                            IndependentMotionType::Bezier { control_points, durations, current_segment, current_segment_time } => {
                                *current_segment_time += dt;
                                
                                while *current_segment < durations.len() && 
                                      *current_segment_time > durations[*current_segment] {
                                    *current_segment_time -= durations[*current_segment];
                                    *current_segment += 1;
                                    
                                    if *current_segment >= durations.len() {
                                        *current_segment = 0;
                                        *current_segment_time = 0.0;
                                    }
                                }
                                
                                let segment_start = *current_segment * 3;
                                if segment_start + 3 >= control_points.len() {
                                    Some(poi.position.clone())
                                } else {
                                    let p0 = &control_points[segment_start];
                                    let p1 = &control_points[segment_start + 1];
                                    let p2 = &control_points[segment_start + 2];
                                    let p3 = &control_points[segment_start + 3];
                                    
                                    let t = if durations[*current_segment] > 0.0 {
                                        (*current_segment_time / durations[*current_segment]).clamp(0.0, 1.0)
                                    } else {
                                        0.0
                                    };
                                    
                                    let t2 = t * t;
                                    let t3 = t2 * t;
                                    let mt = 1.0 - t;
                                    let mt2 = mt * mt;
                                    let mt3 = mt2 * mt;
                                    
                                    Some(Vector3::new(
                                        mt3 * p0.x + 3.0 * mt2 * t * p1.x + 3.0 * mt * t2 * p2.x + t3 * p3.x,
                                        mt3 * p0.y + 3.0 * mt2 * t * p1.y + 3.0 * mt * t2 * p2.y + t3 * p3.y,
                                        mt3 * p0.z + 3.0 * mt2 * t * p1.z + 3.0 * mt * t2 * p2.z + t3 * p3.z
                                    ))
                                }
                            },
                            IndependentMotionType::Stationary => Some(poi.position.clone()),
                        };
                        new_pos
                    } else {
                        Some(poi.position.clone())
                    }
                },
            };
            
            // Update the last update time
            state.last_update_time = self.current_time;
            
            position_update
        } else {
            None
        };

        // Now update the position if we got one
        if let Some(new_position) = position_update {
            if let Some(poi) = self.pois.get_mut(&poi_id) {
                poi.position = new_position.clone();
                
                // Update spatial index
                self.spatial_index.update_entity_position(
                    poi_id,
                    EntityType::PointOfInterest,
                    &new_position,
                    &self.containers,
                    &self.pois,
                    &self.poi_states
                );
            }
        }
    }
    
    fn update_orbital_marker_position(&mut self, marker_id: u32) {
        if let Some(marker) = self.orbital_markers.get_mut(&marker_id) {
            let container_id = marker.container_id;
            
            if let Some(container) = self.containers.get(&container_id) {
                // Transform local position to global
                let rotated = container.rot_quat.rotate_vector(&marker.local_position);
                marker.global_position = container.position.add(&rotated);
            }
        }
    }
    
    pub fn update_spatial_index(&mut self) {
        // Rebuild spatial index from scratch
        let system_size = self.get_system_size();
        self.spatial_index.rebuild(
            system_size,
            &self.containers,
            &self.pois,
            &self.poi_states
        );
        
        // Alternative implementation: Update existing entities in place
        // This avoids a full rebuild which may be expensive
        /*
        // Update container positions in spatial index
        for (id, _) in &self.containers {
            if let Some(position) = self.get_entity_position(*id, EntityType::ObjectContainer) {
                self.spatial_index.update_entity_position(
                    *id,
                    EntityType::ObjectContainer,
                    &position,
                    &self.containers,
                    &self.pois,
                    &self.poi_states
                );
            }
        }
        
        // Update POI positions in spatial index
        for (id, _) in &self.pois {
            if let Some(position) = self.get_entity_position(*id, EntityType::PointOfInterest) {
                self.spatial_index.update_entity_position(
                    *id,
                    EntityType::PointOfInterest,
                    &position,
                    &self.containers,
                    &self.pois,
                    &self.poi_states
                );
            }
        }
        */
    }
    
    // Helper method to determine the overall system size
    fn get_system_size(&self) -> f64 {
        let mut max_distance = 0.0;
        
        // Find the most distant entity from origin
        for (_, container) in &self.containers {
            let distance = container.position.magnitude();
            if distance > max_distance {
                max_distance = distance;
            }
        }
        
        for (id, _) in &self.pois {
            if let Some(position) = self.get_entity_position(*id, EntityType::PointOfInterest) {
                let distance = position.magnitude();
                if distance > max_distance {
                    max_distance = distance;
                }
            }
        }
        
        // Add a safety margin
        max_distance * 2.0
    }
    
    // Update rebuild_spatial_index method
    pub fn rebuild_spatial_index(&mut self) {
        let system_size = 1_000_000_000_000.0; // 1,000,000,000 km
        self.spatial_index.rebuild(
            system_size, 
            &self.containers, 
            &self.pois, 
            &self.poi_states
        );
        self.last_index_update = self.current_time;
    }

    // Helper method to get entity position for spatial indexing
    pub fn get_entity_position(&self, entity_id: u32, entity_type: EntityType) -> Option<Vector3> {
        match entity_type {
            EntityType::ObjectContainer => {
                self.containers.get(&entity_id).map(|c| c.position.clone())
            },
            EntityType::PointOfInterest => {
                self.pois.get(&entity_id).map(|p| p.position.clone())
            },
        }
    }
}

impl InterstellarNavigationSystem {
    pub fn calculate_path(&mut self, start_id: u32, start_type: EntityType, end_id: u32, end_type: EntityType, constraints: Option<NavigationConstraints>) -> NavigationPath {
        let constraints = constraints.unwrap_or(self.default_constraints);
        
        // Check if end entity is a moon, requiring parent-first routing
        if end_type == EntityType::ObjectContainer {
            if let Some(container) = self.containers.get(&end_id) {
                if container.container_type == ContainerType::Moon {
                    if let Some(state) = self.container_states.get(&end_id) {
                        if let Some(parent_id) = state.parent_id {
                            return self.find_path_to_moon(start_id, start_type, end_id, parent_id, constraints);
                        }
                    }
                }
            }
        }
        
        // Extract positions
        let start_pos = match start_type {
            EntityType::ObjectContainer => {
                if let Some(container) = self.containers.get(&start_id) {
                    container.position.clone()
                } else {
                    return self.empty_path(); // Invalid ID
                }
            },
            EntityType::PointOfInterest => {
                if let Some(poi) = self.pois.get(&start_id) {
                    poi.position.clone()
                } else {
                    return self.empty_path(); // Invalid ID
                }
            },
        };
        
        let end_pos = match end_type {
            EntityType::ObjectContainer => {
                if let Some(container) = self.containers.get(&end_id) {
                    container.position.clone()
                } else {
                    return self.empty_path(); // Invalid ID
                }
            },
            EntityType::PointOfInterest => {
                if let Some(poi) = self.pois.get(&end_id) {
                    poi.position.clone()
                } else {
                    return self.empty_path(); // Invalid ID
                }
            },
        };
        
        // Check direct line of sight between start and end
        let distance = start_pos.distance(&end_pos);
        
        if self.check_line_of_sight(&start_pos, &end_pos) {
            // Direct path is possible
            let travel_type = if distance > constraints.max_hydrogen_distance {
                TravelType::Quantum
            } else {
                TravelType::Hydrogen
            };
            
            let travel_time = match travel_type {
                TravelType::Quantum => distance / 150_000_000.0, // Default quantum speed
                TravelType::QuantumBoost => 0.0, // Instantaneous
                TravelType::Hydrogen => distance / 250.0, // Default hydrogen speed
            };
            
            let start_waypoint = Waypoint {
                entity_id: start_id,
                entity_type: start_type,
                position: start_pos,
                arrival_time: 0.0,
                travel_type,
                distance: 0.0,
            };
            
            let end_waypoint = Waypoint {
                entity_id: end_id,
                entity_type: end_type,
                position: end_pos,
                arrival_time: travel_time,
                travel_type,
                distance,
            };
            
            return NavigationPath {
                waypoints: vec![start_waypoint, end_waypoint],
                total_distance: distance,
                total_time: travel_time,
                start_time: self.current_time,
                propulsion_changes: vec![(0, travel_type)],
                los_checks: vec![true],
            };
        }
        
        // No direct LOS - use A* pathfinding
        let path = self.find_path_astar(start_id, start_type, end_id, end_type, constraints.clone());
        
        // Apply path optimization if requested
        if constraints.prefer_safety {
            self.optimize_path_for_safety(&path, constraints.safety_margin)
        } else if constraints.prefer_segments {
            self.optimize_path(&path, "segments")
        } else {
            // Already optimized for distance by A*
            path
        }
    }
    
    pub fn find_path_to_moon(&self, start_id: u32, start_type: EntityType, moon_id: u32, parent_id: u32, constraints: NavigationConstraints) -> NavigationPath {
        // Get positions using position resolution
        let start_pos = match self.get_entity_position(start_id, start_type) {
            Some(pos) => pos,
            None => return self.empty_path() // Invalid ID
        };
        
        let moon_pos = match self.get_entity_position(moon_id, EntityType::ObjectContainer) {
            Some(pos) => pos,
            None => return self.empty_path() // Invalid ID
        };
        
        // Check if direct LOS exists to the moon
        let has_direct_los = self.check_line_of_sight(&start_pos, &moon_pos);
        
        if has_direct_los {
            // Direct path to moon is possible
            return self.find_path_astar(start_id, start_type, moon_id, EntityType::ObjectContainer, constraints);
        }
        
        // No direct LOS - must route through parent planet's orbital markers
        // Find nearest OM of parent planet to our line of approach
        if let Some(parent) = self.containers.get(&parent_id) {
            if let Some(parent_state) = self.container_states.get(&parent_id) {
                let parent_pos = self.get_entity_position(parent_id, EntityType::ObjectContainer)
                    .unwrap_or_else(|| parent.position.clone());
                
                let direction_to_parent = parent_pos.sub(&start_pos).normalized();
                
                // Find most aligned orbital marker
                let mut best_om_id = None;
                let mut best_alignment = -1.0; // Dot product, higher is better aligned
                
                for &om_id in &parent_state.orbital_markers {
                    if let Some(om_pos) = self.get_entity_position(om_id, EntityType::PointOfInterest) {
                        let om_direction = om_pos.sub(&parent_pos).normalized();
                        
                        // Calculate alignment between our approach vector and OM position
                        let alignment = direction_to_parent.dot(&om_direction);
                        
                        if alignment > best_alignment {
                            best_alignment = alignment;
                            best_om_id = Some(om_id);
                        }
                    }
                }
                
                // Create multi-segment path: first to parent's OM, then to moon
                if let Some(om_id) = best_om_id {
                    // First segment: start to parent's OM
                    let path_to_om = self.find_path_astar(
                        start_id,
                        start_type,
                        om_id,
                        EntityType::PointOfInterest,
                        constraints.clone()
                    );
                    
                    // Second segment: OM to moon
                    let path_to_moon = self.find_path_astar(
                        om_id,
                        EntityType::PointOfInterest,
                        moon_id,
                        EntityType::ObjectContainer,
                        constraints
                    );
                    
                    // Combine paths
                    return self.combine_paths(path_to_om, path_to_moon);
                }
            }
        }
        
        // Fallback: direct path to moon (should never happen if parent has OMs)
        self.find_path_astar(start_id, start_type, moon_id, EntityType::ObjectContainer, constraints)
    }
    
    // Helper method to combine two navigation paths
    fn combine_paths(&self, first_path: NavigationPath, second_path: NavigationPath) -> NavigationPath {
        // Empty path handling
        if first_path.waypoints.is_empty() {
            return second_path;
        }
        if second_path.waypoints.is_empty() {
            return first_path;
        }
        
        // Combine waypoints (skipping duplicate at junction)
        let mut combined_waypoints = first_path.waypoints.clone();
        combined_waypoints.extend(second_path.waypoints.iter().skip(1).cloned());
        
        // Calculate total distance and time
        let total_distance = first_path.total_distance + second_path.total_distance;
        let total_time = first_path.total_time + second_path.total_time;
        
        // Adjust second path's propulsion changes to account for first path's waypoints
        let mut combined_propulsion_changes = first_path.propulsion_changes.clone();
        let offset = first_path.waypoints.len() - 1;
        
        for (idx, prop_type) in second_path.propulsion_changes.iter().skip(1) {
            combined_propulsion_changes.push((idx + offset, *prop_type));
        }
        
        // Combine LOS checks
        let mut combined_los_checks = first_path.los_checks.clone();
        combined_los_checks.extend(second_path.los_checks.iter());
        
        NavigationPath {
            waypoints: combined_waypoints,
            total_distance,
            total_time,
            start_time: first_path.start_time,
            propulsion_changes: combined_propulsion_changes,
            los_checks: combined_los_checks,
        }
    }
    
    // Placeholder method for empty paths
    fn empty_path(&self) -> NavigationPath {
        NavigationPath {
            waypoints: Vec::new(),
            total_distance: 0.0,
            total_time: 0.0,
            start_time: self.current_time,
            propulsion_changes: Vec::new(),
            los_checks: Vec::new(),
        }
    }
    
    // A* pathfinding algorithm for optimal navigation
    pub fn find_path_astar(
        &self,
        start_id: u32,
        start_type: EntityType,
        end_id: u32,
        end_type: EntityType,
        constraints: NavigationConstraints,
    ) -> NavigationPath {
        // Extract positions
        let start_pos = self.get_entity_position(start_id, start_type)
            .unwrap_or_else(|| Vector3::zero());
            
        let end_pos = self.get_entity_position(end_id, end_type)
            .unwrap_or_else(|| Vector3::zero());
        
        // Initialize A* data structures
        let mut open_set = BinaryHeap::new();
        let mut closed_set = Vec::new();
        let mut g_scores = HashMap::new();
        
        // Create start node
        let start_node = PathNode {
            entity_id: start_id,
            entity_type: start_type,
            position: start_pos.clone(),
            g_score: 0.0,
            f_score: start_pos.distance(&end_pos),
            parent: None,
            travel_type: TravelType::Hydrogen, // Initial travel type
        };
        
        open_set.push(start_node.clone());
        g_scores.insert((start_id, start_type), 0.0);
        
        // A* search
        while let Some(current) = open_set.pop() {
            let current_key = (current.entity_id, current.entity_type);
            
            // Goal check
            if current_key == (end_id, end_type) {
                return self.reconstruct_path(closed_set, current, start_id, start_type, end_id, end_type);
            }
            
            closed_set.push(current.clone());
            
            // Get neighbors
            let neighbors = self.get_potential_waypoints(&current.position, current.entity_id, current.entity_type, end_id, end_type);
            
            for neighbor in neighbors {
                let neighbor_key = (neighbor.entity_id, neighbor.entity_type);
                
                // Skip if already processed
                if closed_set.iter().any(|node| (node.entity_id, node.entity_type) == neighbor_key) {
                    continue;
                }
                
                // Calculate distance and travel type
                let distance = current.position.distance(&neighbor.position);
                
                // Determine travel type based on distance and constraints
                let travel_type = if self.is_quantum_activation_allowed(&current.position) && 
                                    distance > constraints.max_hydrogen_distance {
                    // Check if we have LOS for quantum travel
                    if self.check_line_of_sight(&current.position, &neighbor.position) {
                        TravelType::Quantum
                    } else {
                        TravelType::Hydrogen // No LOS, must use hydrogen propulsion
                    }
                } else {
                    TravelType::Hydrogen
                };
                
                // Calculate cost
                let mut travel_cost = match travel_type {
                    TravelType::Quantum => distance / 150_000_000.0, // Time cost
                    TravelType::QuantumBoost => 0.01, // Small fixed cost
                    TravelType::Hydrogen => distance / 250.0, // Time cost
                };
                
                // Apply penalties based on constraints
                travel_cost = self.apply_constraints_penalties(
                    &current.position, 
                    &neighbor.position, 
                    travel_cost, 
                    &constraints
                );
                
                let tentative_g = g_scores.get(&current_key).unwrap_or(&0.0) + travel_cost;
                
                if tentative_g < *g_scores.get(&neighbor_key).unwrap_or(&f64::INFINITY) {
                    // This path is better
                    g_scores.insert(neighbor_key, tentative_g);
                    
                    let h_score = neighbor.position.distance(&end_pos);
                    let f_score = tentative_g + h_score;
                    
                    let new_node = PathNode {
                        entity_id: neighbor.entity_id,
                        entity_type: neighbor.entity_type,
                        position: neighbor.position.clone(),
                        g_score: tentative_g,
                        f_score,
                        parent: Some(closed_set.len() - 1), // Index of current in closed_set
                        travel_type,
                    };
                    
                    open_set.push(new_node);
                }
            }
        }
        
        // No path found - return direct path as fallback with warning
        let distance = start_pos.distance(&end_pos);
        let travel_type = if distance > constraints.max_hydrogen_distance {
            TravelType::Quantum
        } else {
            TravelType::Hydrogen
        };
        
        let travel_time = match travel_type {
            TravelType::Quantum => distance / 150_000_000.0,
            TravelType::QuantumBoost => 0.0,
            TravelType::Hydrogen => distance / 250.0,
        };
        
        let start_waypoint = Waypoint {
            entity_id: start_id,
            entity_type: start_type,
            position: start_pos,
            arrival_time: 0.0,
            travel_type,
            distance: 0.0,
        };
        
        let end_waypoint = Waypoint {
            entity_id: end_id,
            entity_type: end_type,
            position: end_pos,
            arrival_time: travel_time,
            travel_type,
            distance,
        };
        
        NavigationPath {
            waypoints: vec![start_waypoint, end_waypoint],
            total_distance: distance,
            total_time: travel_time,
            start_time: self.current_time,
            propulsion_changes: vec![(0, travel_type)],
            los_checks: vec![false], // No LOS guaranteed
        }
    }
    
    // Apply penalties based on navigation constraints
    fn apply_constraints_penalties(&self, start: &Vector3, end: &Vector3, base_cost: f64, constraints: &NavigationConstraints) -> f64 {
        let mut total_cost = base_cost;
        
        // Add penalty for low altitude paths if we want to avoid them
        if constraints.avoid_atmospheres {
            for (id, container) in &self.containers {
                if container.body_radius > 0.0 {
                    let _state =
                        if let Some(state) = self.container_states.get(id) {
                            state
                        } else {
                            continue;
                        };
                    
                    let closest_approach = self.closest_approach_distance(start, end, id);
                    let min_safe_distance = container.body_radius + constraints.min_altitude;
                    
                    if closest_approach < min_safe_distance {
                        // Path violates minimum altitude - apply significant penalty
                        total_cost *= 10.0;
                        break;
                    }
                }
            }
        }
        
        // Apply safety margin penalties if safety is prioritized
        if constraints.prefer_safety {
            for (id, container) in &self.containers {
                if container.body_radius > 0.0 {
                    let closest_approach = self.closest_approach_distance(start, end, id);
                    let safe_distance = container.body_radius + constraints.safety_margin;
                    
                    if closest_approach < safe_distance {
                        // Distance penalty increases as we get closer to the object
                        let penalty_factor = (safe_distance / closest_approach).powi(2);
                        total_cost *= penalty_factor;
                        break;
                    }
                }
            }
        }
        
        total_cost
    }
    
    // Calculate the closest approach distance from a line segment to a celestial body
    fn closest_approach_distance(&self, start: &Vector3, end: &Vector3, container_id: &u32) -> f64 {
        if let Some(container) = self.containers.get(container_id) {
            let body_center = &container.position;
            
            // Vector from start to end
            let path_vector = end.sub(start);
            let path_length = path_vector.magnitude();
            
            if path_length < EPSILON {
                // Start and end are effectively the same point
                return start.distance(body_center);
            }
            
            // Normalize path vector
            let path_direction = path_vector.scale(1.0 / path_length);
            
            // Vector from start to body center
            let start_to_center = body_center.sub(start);
            
            // Projection of start_to_center onto path_direction
            let projection_length = start_to_center.dot(&path_direction);
            
            // Clamp projection to path length
            let clamped_projection = projection_length.clamp(0.0, path_length);
            
            // Point of closest approach
            let closest_point = Vector3::new(
                start.x + path_direction.x * clamped_projection,
                start.y + path_direction.y * clamped_projection,
                start.z + path_direction.z * clamped_projection,
            );
            
            // Distance from closest point to body center
            closest_point.distance(body_center)
        } else {
            // If container doesn't exist, return infinity
            f64::INFINITY
        }
    }
    
    // Reconstruct path from A* search results
    fn reconstruct_path(&self, closed_set: Vec<PathNode>, goal: PathNode, start_id: u32, start_type: EntityType, end_id: u32, end_type: EntityType) -> NavigationPath {
        let mut path = Vec::new();
        let mut current = goal;
        let mut total_distance = 0.0;
        let mut propulsion_changes = Vec::new();
        let mut los_checks = Vec::new();
        let mut current_travel_type = current.travel_type;
        
        propulsion_changes.push((0, current_travel_type));
        
        // Traverse backwards from goal to start
        while let Some(parent_idx) = current.parent {
            let parent = &closed_set[parent_idx];
            
            let distance = current.position.distance(&parent.position);
            total_distance += distance;
            
            // Check for propulsion changes
            if parent.travel_type != current_travel_type {
                current_travel_type = parent.travel_type;
                propulsion_changes.push((path.len(), current_travel_type));
            }
            
            // Check line of sight
            los_checks.push(self.check_line_of_sight(&current.position, &parent.position));
            
            path.push(current);
            current = parent.clone();
        }
        
        // Add the start node
        path.push(current);
        
        // Reverse the path to go from start to goal
        path.reverse();
        los_checks.reverse();
        
        // Convert PathNodes to Waypoints
        let mut waypoints = Vec::new();
        let mut cumulative_time = 0.0;
        let mut prev_position = self.get_entity_position(start_id, start_type)
            .unwrap_or_else(|| Vector3::zero());
        
        for (i, node) in path.iter().enumerate() {
            let distance = if i == 0 { 0.0 } else { node.position.distance(&prev_position) };
            
            let travel_time = match node.travel_type {
                TravelType::Quantum => distance / 150_000_000.0,
                TravelType::QuantumBoost => 0.0,
                TravelType::Hydrogen => distance / 250.0,
            };
            
            cumulative_time += travel_time;
            
            let waypoint = Waypoint {
                entity_id: node.entity_id,
                entity_type: node.entity_type,
                position: node.position.clone(),
                arrival_time: cumulative_time,
                travel_type: node.travel_type,
                distance,
            };
            
            waypoints.push(waypoint);
            prev_position = node.position.clone();
        }
        
        // Ensure the end entity is the actual goal
        if let Some(last) = waypoints.last_mut() {
            last.entity_id = end_id;
            last.entity_type = end_type;
        }
        
        NavigationPath {
            waypoints,
            total_distance,
            total_time: cumulative_time,
            start_time: self.current_time,
            propulsion_changes,
            los_checks,
        }
    }
    
    // Get potential waypoints for pathfinding
    fn get_potential_waypoints(&self, position: &Vector3, entity_id: u32, entity_type: EntityType, goal_id: u32, goal_type: EntityType) -> Vec<PathNode> {
        let mut waypoints = Vec::new();
        
        // Find nearby celestial bodies
        let nearby_entities =
            self.spatial_index.query_radius(
                position,
                50_000_000.0, // 50,000 km radius
                &self.containers,
                &self.pois,
                &self.poi_states
            );

        for (id, ty) in nearby_entities {
            // Skip current entity
            if id == entity_id && ty == entity_type {
                continue;
            }
            
            match ty {
                EntityType::ObjectContainer => {
                    if let Some(container) = self.containers.get(&id) {
                        // For planetary bodies, add their orbital markers
                        if container.container_type == ContainerType::Planet || 
                           container.container_type == ContainerType::Moon {
                            if let Some(state) = self.container_states.get(&id) {
                                for &om_id in &state.orbital_markers {
                                    if let Some(om) = self.orbital_markers.get(&om_id) {
                                        waypoints.push(PathNode {
                                            entity_id: om_id,
                                            entity_type: EntityType::PointOfInterest,
                                            position: om.global_position.clone(),
                                            g_score: 0.0,
                                            f_score: 0.0,
                                            parent: None,
                                            travel_type: TravelType::Quantum,
                                        });
                                    }
                                }
                            }
                        }
                        
                        // For stations, add them directly
                        if container.container_type == ContainerType::NavalStation || 
                           container.container_type == ContainerType::RefineryStation ||
                           container.container_type == ContainerType::RestStop {
                            waypoints.push(PathNode {
                                entity_id: id,
                                entity_type: EntityType::ObjectContainer,
                                position: container.position.clone(),
                                g_score: 0.0,
                                f_score: 0.0,
                                parent: None,
                                travel_type: TravelType::Quantum,
                            });
                        }
                    }
                },
                EntityType::PointOfInterest => {
                    if let Some(poi) = self.pois.get(&id) {
                        // Only add POIs with quantum travel markers
                        if poi.has_qt_marker {
                            waypoints.push(PathNode {
                                entity_id: id,
                                entity_type: EntityType::PointOfInterest,
                                position: poi.position.clone(),
                                g_score: 0.0,
                                f_score: 0.0,
                                parent: None,
                                travel_type: TravelType::Quantum,
                            });
                        }
                    }
                },
            }
        }
        
        // Always consider the goal as a potential waypoint
        let goal_pos = match goal_type {
            EntityType::ObjectContainer => {
                if let Some(container) = self.containers.get(&goal_id) {
                    container.position.clone()
                } else {
                    Vector3::zero() // Fallback
                }
            },
            EntityType::PointOfInterest => {
                if let Some(poi) = self.pois.get(&goal_id) {
                    poi.position.clone()
                } else {
                    Vector3::zero() // Fallback
                }
            },
        };
        
        waypoints.push(PathNode {
            entity_id: goal_id,
            entity_type: goal_type,
            position: goal_pos,
            g_score: 0.0,
            f_score: 0.0,
            parent: None,
            travel_type: TravelType::Quantum,
        });
        
        waypoints
    }
    
    // Check if line of sight exists between two points
    pub fn check_line_of_sight(&self, start: &Vector3, end: &Vector3) -> bool {
        let direction = end.sub(start);
        let distance = direction.magnitude();
        
        if distance < 1.0 {
            return true; // Same position
        }
        
        let normalized_dir = direction.scale(1.0 / distance);
        
        // Cast ray using modified ray_cast implementation
        let ray_results = self.spatial_index.ray_cast(
            start, &normalized_dir, distance, 
            &self.containers, &self.pois, &self.poi_states
        );
        
        // Check for obstacles
        for ((id, ty), _) in ray_results {
            if ty == EntityType::ObjectContainer {
                if let Some(container) = self.containers.get(&id) {
                    if container.body_radius > 0.0 {
                        return false; // Path intersects celestial body
                    }
                }
            }
        }
        
        true // No obstructions found
    }
    
    // Check if detailed line of sight exists with multiple sample points
    pub fn check_detailed_line_of_sight(&self, start: &Vector3, end: &Vector3, interval: f64) -> bool {
        let direction = end.sub(start);
        let distance = direction.magnitude();
        
        if distance < interval {
            return self.check_line_of_sight(start, end); // Simple check for short distances
        }
        
        let normalized_dir = direction.scale(1.0 / distance);
        
        // Number of sample points along the path
        let samples = (distance / interval).ceil() as usize;
        
        // Check each interval for obstructions
        for i in 0..samples {
            let t = i as f64 * interval;
            let sample_point = Vector3::new(
                start.x + normalized_dir.x * t,
                start.y + normalized_dir.y * t,
                start.z + normalized_dir.z * t,
            );
            
            // Check against all celestial bodies using consistent position resolution
            for (id, container) in &self.containers {
                // Get proper container position
                let container_position = self.get_entity_position(*id, EntityType::ObjectContainer)
                    .unwrap_or_else(|| container.position.clone());
                
                if container.body_radius > 0.0 {
                    if let Some(state) = self.container_states.get(id) {
                        let distance_to_center = sample_point.distance(&container_position);
                        
                        // Consider atmosphere if present, otherwise use body radius
                        let check_radius = if state.atmosphere_radius > container.body_radius {
                            state.atmosphere_radius
                        } else {
                            container.body_radius
                        };
                        
                        if distance_to_center < check_radius {
                            return false; // Path intersects celestial body
                        }
                    }
                }
            }
        }
        
        true // No obstructions found
    }
    
    // Check if quantum drive activation is allowed at a position
    pub fn is_quantum_activation_allowed(&self, position: &Vector3) -> bool {
        // Check against all celestial bodies
        for (id, container) in &self.containers {
            // Get proper container position
            let container_position = self.get_entity_position(*id, EntityType::ObjectContainer)
                .unwrap_or_else(|| container.position.clone());
            
            if let Some(state) = self.container_states.get(id) {
                let distance_to_center = position.distance(&container_position);
                
                // Determine safety radius based on container type
                let safety_radius = state.safety_radius;
                
                if distance_to_center < safety_radius {
                    return false; // Too close to celestial body
                }
            }
        }
        
        true // Safe to activate quantum drive
    }
    
    // Update navigation path to reflect current positions
    pub fn update_path(&mut self, path_id: u32, path: NavigationPath) {
        // Recalculate global positions for all waypoints
        let mut updated_waypoints = Vec::new();
        let mut total_distance = 0.0;
        let mut cumulative_time = 0.0;
        let mut prev_position = path.waypoints.first().map(|w| w.position.clone()).unwrap_or(Vector3::zero());
        
        for waypoint in &path.waypoints {
            // Use the consistent position resolution method
            let updated_position = self.get_entity_position(waypoint.entity_id, waypoint.entity_type)
                .unwrap_or_else(|| waypoint.position.clone());
            
            let distance = updated_position.distance(&prev_position);
            total_distance += distance;
            
            let travel_time = match waypoint.travel_type {
                TravelType::Quantum => distance / 150_000_000.0,
                TravelType::QuantumBoost => 0.0,
                TravelType::Hydrogen => distance / 250.0,
            };
            
            cumulative_time += travel_time;
            
            let updated_waypoint = Waypoint {
                entity_id: waypoint.entity_id,
                entity_type: waypoint.entity_type,
                position: updated_position.clone(),
                arrival_time: cumulative_time,
                travel_type: waypoint.travel_type,
                distance,
            };
            
            updated_waypoints.push(updated_waypoint);
            prev_position = updated_position;
        }
        
        // Check if LOS constraints still hold
        let mut updated_los_checks = Vec::new();
        
        for i in 1..updated_waypoints.len() {
            let has_los = self.check_line_of_sight(
                &updated_waypoints[i-1].position,
                &updated_waypoints[i].position
            );
            updated_los_checks.push(has_los);
        }
        
        // Update the path
        let updated_path = NavigationPath {
            waypoints: updated_waypoints,
            total_distance,
            total_time: cumulative_time,
            start_time: path.start_time,
            propulsion_changes: path.propulsion_changes.clone(),
            los_checks: updated_los_checks,
        };
        
        self.active_paths.insert(path_id, updated_path);
    }
    
    // Optimize path by reducing number of waypoints
    pub fn optimize_path(&self, path: &NavigationPath, priority: &str) -> NavigationPath {
        match priority {
            "distance" => {
                // Already optimized for distance by A*
                path.clone()
            },
            "segments" => {
                // Try to reduce number of waypoints by checking if we can skip some
                let mut optimized_waypoints = Vec::new();
                let mut i = 0;
                
                while i < path.waypoints.len() {
                    optimized_waypoints.push(path.waypoints[i].clone());
                    
                    // Try to skip ahead as far as possible with LOS
                    let mut furthest_visible = i;
                    
                    for j in (i+2)..path.waypoints.len() {
                        if self.check_line_of_sight(&path.waypoints[i].position, &path.waypoints[j].position) &&
                           self.check_altitude_constraints(&path.waypoints[i].position, &path.waypoints[j].position, 
                                                         self.default_constraints.min_altitude) {
                            furthest_visible = j;
                        } else {
                            // Stop at first obstruction
                            break;
                        }
                    }
                    
                    if furthest_visible > i + 1 {
                        i = furthest_visible;
                    } else {
                        i += 1;
                    }
                }
                
                // Recalculate distances, times, etc.
                let mut total_distance = 0.0;
                let mut cumulative_time = 0.0;
                let mut prev_position = optimized_waypoints.first()
                    .map(|w| w.position.clone())
                    .unwrap_or_else(|| Vector3::zero());
                let mut propulsion_changes = Vec::new();
                let mut los_checks = Vec::new();
                let mut current_travel_type = optimized_waypoints.first()
                    .map(|w| w.travel_type)
                    .unwrap_or(TravelType::Hydrogen);

                propulsion_changes.push((0, current_travel_type));

                // Process first waypoint separately
                if !optimized_waypoints.is_empty() {
                    optimized_waypoints[0].distance = 0.0;
                    optimized_waypoints[0].arrival_time = 0.0;
                }

                // Process remaining waypoints
                for i in 1..optimized_waypoints.len() {
                    // Get current position and compute distance
                    let current_position = optimized_waypoints[i].position.clone();
                    let distance = current_position.distance(&prev_position);
                    total_distance += distance;
                    
                    // Determine travel type based on distance and constraints
                    let travel_type = if self.is_quantum_activation_allowed(&prev_position) && 
                                        distance > self.default_constraints.max_hydrogen_distance {
                        TravelType::Quantum
                    } else {
                        TravelType::Hydrogen
                    };
                    
                    if travel_type != current_travel_type {
                        current_travel_type = travel_type;
                        propulsion_changes.push((i, current_travel_type));
                    }
                    
                    let travel_time = match travel_type {
                        TravelType::Quantum => distance / 150_000_000.0,
                        TravelType::QuantumBoost => 0.0,
                        TravelType::Hydrogen => distance / 250.0,
                    };
                    
                    cumulative_time += travel_time;
                    
                    // Update current waypoint
                    {
                        let current = &mut optimized_waypoints[i];
                        current.distance = distance;
                        current.arrival_time = cumulative_time;
                        current.travel_type = travel_type;
                    }
                    
                    // Verify LOS for segment
                    los_checks.push(self.check_line_of_sight(&prev_position, &current_position));
                    
                    // Update for next iteration
                    prev_position = current_position;
                }
                
                NavigationPath {
                    waypoints: optimized_waypoints,
                    total_distance,
                    total_time: cumulative_time,
                    start_time: path.start_time,
                    propulsion_changes,
                    los_checks,
                }
            },
            _ => path.clone(),
        }
    }
    
    // Check if path satisfies altitude constraints
    pub fn check_altitude_constraints(&self, start: &Vector3, end: &Vector3, min_altitude: f64) -> bool {
        for (id, container) in &self.containers {
            if container.body_radius > 0.0 {
                let closest_approach = self.closest_approach_distance(start, end, id);
                let minimum_safe_distance = container.body_radius + min_altitude;
                
                if closest_approach < minimum_safe_distance {
                    return false; // Path violates altitude constraint
                }
            }
        }
        
        true // All altitude constraints satisfied
    }
    
    // Optimize path for safety by adding bypass points
    pub fn optimize_path_for_safety(&self, path: &NavigationPath, safety_margin: f64) -> NavigationPath {
        let mut optimized_waypoints = Vec::new();
        let mut checked_segments = Vec::new();
        
        // Add the first waypoint
        if let Some(first) = path.waypoints.first() {
            optimized_waypoints.push(first.clone());
        } else {
            return path.clone(); // Empty path
        }
        
        // Check each segment for safety
        for i in 1..path.waypoints.len() {
            let prev = &path.waypoints[i-1];
            let current = &path.waypoints[i];
            
            let mut segment_safe = true;
            
            for (id, container) in &self.containers {
                if container.body_radius > 0.0 {
                    let closest_dist = self.closest_approach_distance(&prev.position, &current.position, id);
                    let safe_distance = container.body_radius + safety_margin;
                    
                    if closest_dist < safe_distance {
                        segment_safe = false;
                        
                        // Find a bypass point
                        let bypass_point = self.calculate_safety_bypass(
                            &prev.position, 
                            &current.position, 
                            &container.position, 
                            container.body_radius, 
                            safety_margin
                        );
                        
                        // Generate a temporary ID for the bypass waypoint
                        let bypass_id = 0xFFFFFFFF; // Using max u32 value as temporary ID
                        
                        // Add the bypass waypoint - clone to avoid moving the value
                        let bypass_waypoint = Waypoint {
                            entity_id: bypass_id,
                            entity_type: EntityType::PointOfInterest,
                            position: bypass_point.clone(), // Clone here to prevent move
                            arrival_time: 0.0, // Will be recalculated
                            travel_type: prev.travel_type,
                            distance: 0.0, // Will be recalculated
                        };
                        
                        optimized_waypoints.push(bypass_waypoint);
                        checked_segments.push(false); // LOS needs verification
                        
                        // Use cloned value to avoid borrow of moved value
                        let sub_path = NavigationPath {
                            waypoints: vec![
                                optimized_waypoints.last().unwrap().clone(),
                                current.clone()
                            ],
                            total_distance: bypass_point.distance(&current.position), // No longer a moved value
                            total_time: 0.0, // Not relevant for recursion
                            start_time: path.start_time,
                            propulsion_changes: vec![(0, prev.travel_type)],
                            los_checks: vec![true], // Placeholder
                        };
                        
                        let sub_optimized = self.optimize_path_for_safety(&sub_path, safety_margin);
                        
                        // Add all waypoints except the first (already added as bypass)
                        for wp in sub_optimized.waypoints.iter().skip(1) {
                            optimized_waypoints.push(wp.clone());
                            checked_segments.push(false);
                        }
                        
                        // Skip adding the current waypoint since it's added by recursion
                        break;
                    }
                }
            }
            
            if segment_safe {
                optimized_waypoints.push(current.clone());
                checked_segments.push(true);
            }
        }
        
        // Recalculate distances, times, and LOS checks
        let mut total_distance = 0.0;
        let mut cumulative_time = 0.0;
        let mut propulsion_changes = Vec::new();
        let mut los_checks = Vec::new();
        let mut current_travel_type = optimized_waypoints.first().map(|w| w.travel_type).unwrap_or(TravelType::Hydrogen);
        
        propulsion_changes.push((0, current_travel_type));
        
        // Create separate vector to store updated waypoints
        let mut updated_waypoints = Vec::with_capacity(optimized_waypoints.len());
        updated_waypoints.push(optimized_waypoints[0].clone()); // First waypoint remains unchanged
        
        for i in 1..optimized_waypoints.len() {
            let prev = &optimized_waypoints[i-1];
            let current = &optimized_waypoints[i];
            
            let distance = current.position.distance(&prev.position);
            total_distance += distance;
            
            // Determine travel type based on distance and constraints
            let travel_type = if self.is_quantum_activation_allowed(&prev.position) && 
                                 distance > self.default_constraints.max_hydrogen_distance {
                TravelType::Quantum
            } else {
                TravelType::Hydrogen
            };
            
            if travel_type != current_travel_type {
                current_travel_type = travel_type;
                propulsion_changes.push((i, current_travel_type));
            }
            
            let travel_time = match travel_type {
                TravelType::Quantum => distance / 150_000_000.0,
                TravelType::QuantumBoost => 0.0,
                TravelType::Hydrogen => distance / 250.0,
            };
            
            cumulative_time += travel_time;
            
            // Create new updated waypoint
            let mut updated_waypoint = current.clone();
            updated_waypoint.distance = distance;
            updated_waypoint.arrival_time = cumulative_time;
            updated_waypoint.travel_type = travel_type;
            
            updated_waypoints.push(updated_waypoint);
            
            // Verify LOS for each segment
            los_checks.push(self.check_line_of_sight(&prev.position, &current.position));
        }
        
        NavigationPath {
            waypoints: updated_waypoints,
            total_distance,
            total_time: cumulative_time,
            start_time: path.start_time,
            propulsion_changes,
            los_checks,
        }
    }
    
    // Calculate safety bypass point to avoid celestial bodies
    fn calculate_safety_bypass(
        &self,
        start: &Vector3,
        end: &Vector3,
        obstacle_center: &Vector3,
        obstacle_radius: f64,
        safety_margin: f64
    ) -> Vector3 {
        // Vector from start to end
        let path_vector = end.sub(start);
        let path_length = path_vector.magnitude();
        let path_direction = path_vector.scale(1.0 / path_length);
        
        // Vector from start to obstacle
        let start_to_obstacle = obstacle_center.sub(start);
        
        // Project onto path direction
        let projection = start_to_obstacle.dot(&path_direction);
        
        // Closest point on path to obstacle
        let closest_point = Vector3::new(
            start.x + path_direction.x * projection,
            start.y + path_direction.y * projection,
            start.z + path_direction.z * projection
        );
        
        // Vector from obstacle to closest point
        let obstacle_to_closest = closest_point.sub(obstacle_center);
        let closest_distance = obstacle_to_closest.magnitude();
        
        // Calculate bypass distance
        let safe_distance = obstacle_radius + safety_margin;
        
        // If we're already safe, just return the original point
        if closest_distance >= safe_distance {
            return closest_point;
        }
        
        // Calculate perpendicular direction for evasion
        // First, normalize the vector from obstacle to closest point
        let normal_direction = if closest_distance > EPSILON {
            obstacle_to_closest.scale(1.0 / closest_distance)
        } else {
            // If closest point is at obstacle center, use a perpendicular to the path
            let world_up = Vector3::new(0.0, 0.0, 1.0);
            let perpendicular = path_direction.cross(&world_up);
            
            if perpendicular.magnitude() > EPSILON {
                perpendicular.normalized()
            } else {
                // If path is aligned with world up, use a different reference
                let alt_reference = Vector3::new(0.0, 1.0, 0.0);
                path_direction.cross(&alt_reference).normalized()
            }
        };
        
        // Calculate how far to move out for safety
        let distance_to_add = safe_distance - closest_distance;
        
        // Calculate final bypass point
        Vector3::new(
            closest_point.x + normal_direction.x * distance_to_add * 1.1, // Add 10% extra margin
            closest_point.y + normal_direction.y * distance_to_add * 1.1,
            closest_point.z + normal_direction.z * distance_to_add * 1.1
        )
    }
    
    // Calculate great circle distance on a planet's surface
    pub fn calculate_great_circle_distance(&self, start: &Vector3, end: &Vector3, planet_id: u32) -> f64 {
        if let Some(planet) = self.containers.get(&planet_id) {
            let planet_center = &planet.position;
            let planet_radius = planet.body_radius;
            
            // Convert to spherical coordinates relative to planet center
            let start_relative = start.sub(planet_center);
            let end_relative = end.sub(planet_center);
            
            let start_normalized = start_relative.normalized();
            let end_normalized = end_relative.normalized();
            
            // Calculate angle between vectors (in radians)
            let dot_product = start_normalized.dot(&end_normalized);
            let angle = dot_product.clamp(-1.0, 1.0).acos();
            
            // Great-circle distance
            planet_radius * angle
        } else {
            // If planet doesn't exist, return direct distance
            start.distance(end)
        }
    }
    
    // Navigate through dense clusters using potential field approach
    pub fn navigate_dense_cluster(&self, start: &Vector3, end: &Vector3, safety_distance: f64) -> NavigationPath {
        // Get all entities in the region between start and end
        let midpoint = Vector3::new(
            (start.x + end.x) / 2.0,
            (start.y + end.y) / 2.0,
            (start.z + end.z) / 2.0,
        );
        
        let search_radius = start.distance(end) / 2.0 + 50_000.0; // Add margin

        let entities =
            self.spatial_index.query_radius(
                &midpoint,
                search_radius,
                &self.containers,
                &self.pois,
                &self.poi_states
            );
        
        // If region isn't dense, return direct path
        if entities.len() < 10 {
            // Create temporary entities for start and end
            let start_id = 0xFFFFFFFE;
            let end_id = 0xFFFFFFFF;
            
            let direct_path = self.find_path_astar(
                start_id,
                EntityType::PointOfInterest,
                end_id,
                EntityType::PointOfInterest,
                self.default_constraints.clone()
            );
            
            return direct_path;
        }
        
        // Use potential field pathfinding for dense regions
        let mut current_pos = start.clone();
        let mut waypoints = Vec::new();
        let mut total_distance = 0.0;
        let mut total_time = 0.0;
        
        // Create start waypoint with temporary ID
        let start_id = 0xFFFFFFFE;
        
        waypoints.push(Waypoint {
            entity_id: start_id,
            entity_type: EntityType::PointOfInterest,
            position: start.clone(),
            arrival_time: 0.0,
            travel_type: TravelType::Hydrogen,
            distance: 0.0,
        });
        
        // Number of steps to take through the field
        let max_steps = 100;
        let step_size = start.distance(end) / 10.0;
        
        for step in 0..max_steps {
            // If close enough to destination, add final waypoint and exit
            if current_pos.distance(end) < step_size {
                let distance = current_pos.distance(end);
                total_distance += distance;
                total_time += distance / 250.0; // Hydrogen speed
                
                // Create end waypoint with temporary ID
                let end_id = 0xFFFFFFFF;
                
                waypoints.push(Waypoint {
                    entity_id: end_id,
                    entity_type: EntityType::PointOfInterest,
                    position: end.clone(),
                    arrival_time: total_time,
                    travel_type: TravelType::Hydrogen,
                    distance,
                });
                
                break;
            }
            
            // Attractive force toward goal
            let direction_to_goal = end.sub(&current_pos);
            let distance_to_goal = direction_to_goal.magnitude();
            let normalized_to_goal = direction_to_goal.scale(1.0 / distance_to_goal);
            
            // Attractive force (scaled by distance)
            let attractive_force = normalized_to_goal.scale(step_size);
            
            // Repulsive forces from obstacles
            let mut repulsive_force = Vector3::zero();
            
            for (id, ty) in &entities {
                let (entity_pos, entity_radius) = match ty {
                    EntityType::ObjectContainer => {
                        if let Some(container) = self.containers.get(id) {
                            (container.position.clone(), container.body_radius)
                        } else {
                            continue;
                        }
                    },
                    EntityType::PointOfInterest => {
                        // POIs don't have collision radius
                        continue;
                    },
                };
                
                if entity_radius > 0.0 {
                    let direction_to_entity = current_pos.sub(&entity_pos);
                    let distance_to_entity = direction_to_entity.magnitude();
                    
                    // Skip if too far
                    if distance_to_entity > entity_radius + safety_distance * 2.0 {
                        continue;
                    }
                    
                    let normalized_from_entity = direction_to_entity.scale(1.0 / distance_to_entity);
                    
                    // Repulsive force inversely proportional to distance squared
                    let repulsion_strength =
                        safety_distance * safety_distance
                        / (distance_to_entity - entity_radius).max(0.1).powi(2);
                    
                    repulsive_force = repulsive_force.add(&normalized_from_entity.scale(repulsion_strength));
                }
            }
            
            // Combine forces
            let combined_force = attractive_force.add(&repulsive_force);
            
            // Normalize and scale to step size
            let force_magnitude = combined_force.magnitude();
            let next_step = if force_magnitude > 0.0001 {
                Vector3::new(
                    current_pos.x + combined_force.x / force_magnitude * step_size,
                    current_pos.y + combined_force.y / force_magnitude * step_size,
                    current_pos.z + combined_force.z / force_magnitude * step_size,
                )
            } else {
                // Default to direct path if force is negligible
                Vector3::new(
                    current_pos.x + normalized_to_goal.x * step_size,
                    current_pos.y + normalized_to_goal.y * step_size,
                    current_pos.z + normalized_to_goal.z * step_size,
                )
            };
            
            // Add waypoint if it represents a significant direction change
            let prev_waypoint = waypoints.last().unwrap();
            let prev_direction = next_step.sub(&prev_waypoint.position);
            let prev_waypoint_to_current = current_pos.sub(&prev_waypoint.position);
            
            // Calculate angle change (via dot product of normalized vectors)
            let prev_dir_mag = prev_direction.magnitude();
            let current_dir_mag = prev_waypoint_to_current.magnitude();
            
            if prev_dir_mag > EPSILON && current_dir_mag > EPSILON {
                let angle_change = prev_direction.dot(&prev_waypoint_to_current) / 
                                  (prev_dir_mag * current_dir_mag);
                
                if angle_change < 0.95 || current_pos.distance(&prev_waypoint.position) > step_size * 5.0 {
                    let distance = current_pos.distance(&prev_waypoint.position);
                    total_distance += distance;
                    total_time += distance / 250.0; // Hydrogen speed
                    
                    // Create waypoint with temporary ID based on step number
                    let waypoint_id = 0xFFFF0000 | (step as u32);
                    
                    waypoints.push(Waypoint {
                        entity_id: waypoint_id,
                        entity_type: EntityType::PointOfInterest,
                        position: current_pos.clone(),
                        arrival_time: total_time,
                        travel_type: TravelType::Hydrogen,
                        distance,
                    });
                }
            }
            
            current_pos = next_step;
        }
        
        // If we didn't reach the goal, add a final direct waypoint
        if waypoints.last().unwrap().position.distance(end) > 1.0 {
            let prev_pos = waypoints.last().unwrap().position.clone();
            let distance = prev_pos.distance(end);
            total_distance += distance;
            total_time += distance / 250.0; // Hydrogen speed
            
            // Create end waypoint with temporary ID
            let end_id = 0xFFFFFFFF;
            
            waypoints.push(Waypoint {
                entity_id: end_id,
                entity_type: EntityType::PointOfInterest,
                position: end.clone(),
                arrival_time: total_time,
                travel_type: TravelType::Hydrogen,
                distance,
            });
        }
        
        // Create LOS checks
        let mut los_checks = Vec::new();
        for i in 1..waypoints.len() {
            los_checks.push(self.check_line_of_sight(&waypoints[i-1].position, &waypoints[i].position));
        }
        
        // All hydrogen propulsion
        let propulsion_changes = vec![(0, TravelType::Hydrogen)];
        
        NavigationPath {
            waypoints,
            total_distance,
            total_time,
            start_time: self.current_time,
            propulsion_changes,
            los_checks,
        }
    }
    
    // Update nearest_neighbor method
    pub fn nearest_neighbor(
        &self, 
        position: &Vector3, 
        entity_type_filter: Option<EntityType>
    ) -> Option<(u32, EntityType, f64)> {
        let radius_step = 1000.0; // km
        let mut search_radius = radius_step;
        let max_radius = 10_000_000.0; // 10,000,000 km max search radius
        
        while search_radius < max_radius {
            let entities = self.spatial_index.query_radius(
                position, 
                search_radius, 
                &self.containers, 
                &self.pois, 
                &self.poi_states
            );
            
            let mut nearest = None;
            let mut min_dist = f64::MAX;
            
            for (id, ty) in entities {
                // Apply entity type filter if specified
                if let Some(filter) = entity_type_filter {
                    if ty != filter {
                        continue;
                    }
                }
                
                if let Some(entity_pos) = self.get_entity_position(id, ty) {
                    let dist = position.distance(&entity_pos);
                    if dist < min_dist {
                        min_dist = dist;
                        nearest = Some((id, ty, dist));
                    }
                }
            }
            
            if nearest.is_some() {
                return nearest;
            }
            
            // Increase search radius and try again
            search_radius *= 2.0;
        }
        
        None
    }
    
    // Add validation method for position consistency
    pub fn validate_position_consistency(&self) -> Vec<(u32, EntityType, f64)> {
        let mut inconsistencies = Vec::new();
        
        // Verify container positions
        for (id, _) in &self.containers {
            let direct_position = self.containers.get(id).map(|c| c.position.clone());
            let resolved_position = self.get_entity_position(*id, EntityType::ObjectContainer);
            
            if let (Some(direct), Some(resolved)) = (direct_position, resolved_position) {
                let discrepancy = direct.distance(&resolved);
                if discrepancy > EPSILON {
                    inconsistencies.push((*id, EntityType::ObjectContainer, discrepancy));
                }
            }
        }
        
        // Verify POI positions
        for (id, _) in &self.pois {
            let direct_position = self.pois.get(id).map(|p| p.position.clone());
            let resolved_position = self.get_entity_position(*id, EntityType::PointOfInterest);
            
            if let (Some(direct), Some(resolved)) = (direct_position, resolved_position) {
                // For Static POIs with parents, positions should differ
                if let Some(state) = self.poi_states.get(id) {
                    if let (Some(_), MotionType::Static) = (state.parent_id, state.motion_type) {
                        // Position difference expected - no inconsistency to report
                        continue;
                    }
                }
                
                // For other POIs, positions should match
                let discrepancy = direct.distance(&resolved);
                if discrepancy > EPSILON {
                    inconsistencies.push((*id, EntityType::PointOfInterest, discrepancy));
                }
            }
        }
        
        inconsistencies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_line_of_sight_detection() {
        let mut nav_system = InterstellarNavigationSystem::new();
        
        // Create a planet
        let earth = ObjectContainer {
            id: 1,
            system: System::Sol,
            container_type: ContainerType::Planet,
            name: "Earth".to_string(),
            internal_name: "earth_planet".to_string(),
            position: Vector3::new(0.0, 0.0, 0.0),
            rot_vel: Vector3::new(0.0, 0.0, 7.272e-5),
            rot_adj: Vector3::zero(),
            rot_quat: Quaternion::identity(),
            body_radius: 6_371_000.0,
            om_radius: 6_481_000.0,
            grid_radius: 9_721_500.0,
        };
        
        nav_system.load_containers(vec![earth]);
        
        // Create container state
        nav_system.container_states.insert(1, ContainerState {
            atmosphere_radius: 6_381_000.0,
            safety_radius: 6_381_000.0,
            parent_id: None,
            orbital_markers: Vec::new(),
            mass: 5.97e24,
            orbital_elements: None,
            creation_time: 0.0,
            last_update_time: 0.0,
        });
        
        // Test case 1: Direct line of sight through empty space
        let p1 = Vector3::new(10_000_000.0, 0.0, 0.0);
        let p2 = Vector3::new(-10_000_000.0, 0.0, 0.0);
        
        // Should fail due to Earth in the way
        assert_eq!(nav_system.check_line_of_sight(&p1, &p2), false);
        
        // Test case 2: Path tangent to the planet's surface
        let p3 = Vector3::new(0.0, 10_000_000.0, 0.0);
        let p4 = Vector3::new(0.0, -10_000_000.0, 0.0);
        
        // Should have line of sight
        assert_eq!(nav_system.check_line_of_sight(&p3, &p4), true);
        
        // Test case 3: Path passing close to but not through the planet
        let p5 = Vector3::new(10_000_000.0, 7_000_000.0, 0.0);
        let p6 = Vector3::new(-10_000_000.0, 7_000_000.0, 0.0);
        
        // Clearance of ~7 million meters, should have line of sight
        assert_eq!(nav_system.check_line_of_sight(&p5, &p6), true);
    }
    
    #[test]
    fn test_closest_approach_distance() {
        let mut nav_system = InterstellarNavigationSystem::new();
        
        // Create a planet
        let earth = ObjectContainer {
            id: 1,
            system: System::Sol,
            container_type: ContainerType::Planet,
            name: "Earth".to_string(),
            internal_name: "earth_planet".to_string(),
            position: Vector3::new(0.0, 0.0, 0.0),
            rot_vel: Vector3::new(0.0, 0.0, 7.272e-5),
            rot_adj: Vector3::zero(),
            rot_quat: Quaternion::identity(),
            body_radius: 6_371_000.0,
            om_radius: 6_481_000.0,
            grid_radius: 9_721_500.0,
        };
        
        nav_system.load_containers(vec![earth]);
        
        // Path directly through center
        let start = Vector3::new(-10_000_000.0, 0.0, 0.0);
        let end = Vector3::new(10_000_000.0, 0.0, 0.0);
        
        let closest = nav_system.closest_approach_distance(&start, &end, &1);
        assert!((closest - 0.0).abs() < 1e-10);
        
        // Path at exact tangent
        let start_tangent = Vector3::new(-10_000_000.0, 6_371_000.0, 0.0);
        let end_tangent = Vector3::new(10_000_000.0, 6_371_000.0, 0.0);
        
        let closest_tangent = nav_system.closest_approach_distance(&start_tangent, &end_tangent, &1);
        assert!((closest_tangent - 6_371_000.0).abs() < 1e-10);
        
        // Path missing planet
        let start_miss = Vector3::new(-10_000_000.0, 10_000_000.0, 0.0);
        let end_miss = Vector3::new(10_000_000.0, 10_000_000.0, 0.0);
        
        let closest_miss = nav_system.closest_approach_distance(&start_miss, &end_miss, &1);
        assert!((closest_miss - 10_000_000.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_quantum_activation_constraints() {
        let mut nav_system = InterstellarNavigationSystem::new();
        
        // Create a planet with atmosphere
        let earth = ObjectContainer {
            id: 1,
            system: System::Sol,
            container_type: ContainerType::Planet,
            name: "Earth".to_string(),
            internal_name: "earth_planet".to_string(),
            position: Vector3::new(0.0, 0.0, 0.0),
            rot_vel: Vector3::new(0.0, 0.0, 7.272e-5),
            rot_adj: Vector3::zero(),
            rot_quat: Quaternion::identity(),
            body_radius: 6_371_000.0,
            om_radius: 6_481_000.0,
            grid_radius: 9_721_500.0,
        };
        
        nav_system.load_containers(vec![earth]);
        
        // Create container state with atmosphere
        nav_system.container_states.insert(1, ContainerState {
            atmosphere_radius: 6_381_000.0,
            safety_radius: 6_381_000.0,
            parent_id: None,
            orbital_markers: Vec::new(),
            mass: 5.97e24,
            orbital_elements: None,
            creation_time: 0.0,
            last_update_time: 0.0,
        });
        
        // Test inside atmosphere
        let pos_inside = Vector3::new(0.0, 6_375_000.0, 0.0);
        assert_eq!(nav_system.is_quantum_activation_allowed(&pos_inside), false);
        
        // Test at atmosphere boundary
        let pos_boundary = Vector3::new(0.0, 6_381_000.0, 0.0);
        assert_eq!(nav_system.is_quantum_activation_allowed(&pos_boundary), false);
        
        // Test just outside atmosphere
        let pos_outside = Vector3::new(0.0, 6_382_000.0, 0.0);
        assert_eq!(nav_system.is_quantum_activation_allowed(&pos_outside), true);
        
        // Test far from planet
        let pos_far = Vector3::new(0.0, 10_000_000.0, 0.0);
        assert_eq!(nav_system.is_quantum_activation_allowed(&pos_far), true);
    }
    
    #[test]
    fn test_path_optimization() {
        let nav_system = InterstellarNavigationSystem::new();
        
        // Create two waypoints
        let start_waypoint = Waypoint {
            entity_id: 1,
            entity_type: EntityType::PointOfInterest,
            position: Vector3::new(-10_000_000.0, 0.0, 0.0),
            arrival_time: 0.0,
            travel_type: TravelType::Hydrogen,
            distance: 0.0,
        };
        
        let middle_waypoint = Waypoint {
            entity_id: 2,
            entity_type: EntityType::PointOfInterest,
            position: Vector3::new(0.0, 0.0, 10_000_000.0),
            arrival_time: 40000.0, // 10,000 km at 250 m/s
            travel_type: TravelType::Hydrogen,
            distance: 10_000_000.0,
        };
        
        let end_waypoint = Waypoint {
            entity_id: 3,
            entity_type: EntityType::PointOfInterest,
            position: Vector3::new(10_000_000.0, 0.0, 0.0),
            arrival_time: 80000.0, // Another 10,000 km at 250 m/s
            travel_type: TravelType::Hydrogen,
            distance: 10_000_000.0,
        };
        
        let path = NavigationPath {
            waypoints: vec![start_waypoint, middle_waypoint, end_waypoint],
            total_distance: 20_000_000.0,
            total_time: 80000.0,
            start_time: 0.0,
            propulsion_changes: vec![(0, TravelType::Hydrogen)],
            los_checks: vec![true, true],
        };
        
        // Optimize for segments - should try to go directly from start to end if there's line of sight
        let optimized = nav_system.optimize_path(&path, "segments");
        
        // Since there are no planets in the test setup, we should have direct line of sight
        // This should result in a path with just 2 waypoints
        assert_eq!(optimized.waypoints.len(), 2);
        assert_eq!(optimized.waypoints[0].entity_id, 1); // Start
        assert_eq!(optimized.waypoints[1].entity_id, 3); // End
        
        // The distance should be the direct distance between start and end
        let expected_distance = Vector3::new(-10_000_000.0, 0.0, 0.0).distance(&Vector3::new(10_000_000.0, 0.0, 0.0));
        assert!((optimized.total_distance - expected_distance).abs() < 1.0);
    }
    
    #[test]
    fn test_great_circle_distance() {
        let mut nav_system = InterstellarNavigationSystem::new();
        
        let earth = ObjectContainer {
            id: 1,
            system: System::Sol,
            container_type: ContainerType::Planet,
            name: "Earth".to_string(),
            internal_name: "earth_planet".to_string(),
            position: Vector3::new(0.0, 0.0, 0.0),
            rot_vel: Vector3::new(0.0, 0.0, 7.272e-5),
            rot_adj: Vector3::zero(),
            rot_quat: Quaternion::identity(),
            body_radius: 6_371_000.0,
            om_radius: 6_481_000.0,
            grid_radius: 9_721_500.0,
        };
        
        // Use load_containers instead of direct insertion
        nav_system.load_containers(vec![earth]);
        
        let p1 = Vector3::new(6_371_000.0, 0.0, 0.0);
        let p2 = Vector3::new(-6_371_000.0, 0.0, 0.0);
        let expected_distance = PI * 6_371_000.0;
        let actual_distance = nav_system.calculate_great_circle_distance(&p1, &p2, 1);
        assert!((actual_distance - expected_distance).abs() < 1.0);
        
        let p3 = Vector3::new(6_371_000.0, 0.0, 0.0);
        let p4 = Vector3::new(0.0, 6_371_000.0, 0.0);
        let expected_distance2 = (PI / 2.0) * 6_371_000.0;
        let actual_distance2 = nav_system.calculate_great_circle_distance(&p3, &p4, 1);
        assert!((actual_distance2 - expected_distance2).abs() < 1.0);
        
        let p5 = Vector3::new(6_371_000.0, 0.0, 0.0);
        let p6 = Vector3::new(6_370_000.0, 100_000.0, 0.0);
        let actual_distance3 = nav_system.calculate_great_circle_distance(&p5, &p6, 1);
        assert!(actual_distance3 > 0.0 && actual_distance3 < 100_000.0);
    }
}