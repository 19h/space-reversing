use std::fs::File;
use std::io::{BufReader, Error as IoError, Read};
use std::error::Error as StdError;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::{
    ContainerType, ObjectContainer, PoiType, PointOfInterest, Quaternion, System, Vector3,
};

/// Serializable container representation for data loading
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedContainer {
    pub id: u32,
    pub system: String,
    pub cont_type: String,
    pub name: String,
    pub internal_name: String,
    pub pos_x: f64,
    pub pos_y: f64,
    pub pos_z: f64,
    pub rot_vel_x: f64,
    pub rot_vel_y: f64,
    pub rot_vel_z: f64,
    pub rot_adj_x: f64,
    pub rot_adj_y: f64,
    pub rot_adj_z: f64,
    pub rot_quat_w: f64,
    pub rot_quat_x: f64,
    pub rot_quat_y: f64,
    pub rot_quat_z: f64,
    pub body_radius: f64,
    pub om_radius: f64,
    pub grid_radius: f64,
}

/// Serializable POI representation for data loading
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedPoi {
    id: u32,
    name: String,
    system: String,
    #[serde(default)]
    obj_container: Option<String>,
    poi_type: String,
    class: String,
    pos_x: f64,
    pos_y: f64,
    pos_z: f64,
    has_qt_marker: bool,
    #[serde(default)]
    date_added: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    with_version: Option<String>,
}

/// Data loading error types
#[derive(Debug)]
pub enum DataLoadError {
    IoError(IoError),
    JsonError(serde_json::Error),
    ParseError(String),
}

impl From<IoError> for DataLoadError {
    fn from(error: IoError) -> Self {
        DataLoadError::IoError(error)
    }
}

impl From<serde_json::Error> for DataLoadError {
    fn from(error: serde_json::Error) -> Self {
        DataLoadError::JsonError(error)
    }
}

// Add Display implementation for DataLoadError
impl fmt::Display for DataLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataLoadError::IoError(e) => write!(f, "IO error: {}", e),
            DataLoadError::JsonError(e) => write!(f, "JSON parsing error: {}", e),
            DataLoadError::ParseError(msg) => write!(f, "Data parsing error: {}", msg),
        }
    }
}

// Implement the Error trait for DataLoadError
impl StdError for DataLoadError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            DataLoadError::IoError(e) => Some(e),
            DataLoadError::JsonError(e) => Some(e),
            DataLoadError::ParseError(_) => None,
        }
    }
}

/// Load celestial object containers from JSON file
pub fn load_containers(path: &str) -> Result<Vec<ObjectContainer>, DataLoadError> {
    // Read file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    
    // Parse JSON
    let serialized_containers: Vec<SerializedContainer> = serde_json::from_str(&contents)?;
    
    // Convert to domain objects
    let mut containers = Vec::with_capacity(serialized_containers.len());
    
    for sc in serialized_containers {
        // Parse system
        let system = match System::from_str(&sc.system) {
            Some(sys) => sys,
            None => return Err(DataLoadError::ParseError(format!("Unknown system: {}", sc.system))),
        };
        
        // Parse container type
        let container_type = match ContainerType::from_str(&sc.cont_type) {
            Some(ct) => ct,
            None => return Err(DataLoadError::ParseError(format!("Unknown container type: {}", sc.cont_type))),
        };
        
        let container = ObjectContainer {
            id: sc.id,
            system,
            container_type,
            name: sc.name,
            internal_name: sc.internal_name,
            position: Vector3::new(sc.pos_x, sc.pos_y, sc.pos_z),
            rot_vel: Vector3::new(sc.rot_vel_x, sc.rot_vel_y, sc.rot_vel_z),
            rot_adj: Vector3::new(sc.rot_adj_x, sc.rot_adj_y, sc.rot_adj_z),
            rot_quat: Quaternion::new(sc.rot_quat_w, sc.rot_quat_x, sc.rot_quat_y, sc.rot_quat_z),
            body_radius: sc.body_radius,
            om_radius: sc.om_radius,
            grid_radius: sc.grid_radius,
        };
        
        containers.push(container);
    }
    
    Ok(containers)
}

/// Load points of interest from JSON file
pub fn load_pois(path: &str) -> Result<Vec<PointOfInterest>, DataLoadError> {
    // Read file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    
    // Parse JSON
    let serialized_pois: Vec<SerializedPoi> = serde_json::from_str(&contents)?;
    
    // Convert to domain objects
    let mut pois = Vec::with_capacity(serialized_pois.len());
    
    for sp in serialized_pois {
        // Parse POI type
        let poi_type = match PoiType::from_str(&sp.poi_type) {
            Some(pt) => pt,
            None => return Err(DataLoadError::ParseError(format!("Unknown POI type: {}", sp.poi_type))),
        };
        
        let poi = PointOfInterest {
            id: sp.id,
            name: sp.name,
            system: sp.system,
            obj_container: sp.obj_container,
            poi_type,
            class: sp.class,
            position: Vector3::new(sp.pos_x, sp.pos_y, sp.pos_z),
            has_qt_marker: sp.has_qt_marker,
            date_added: sp.date_added,
            comment: sp.comment,
            with_version: sp.with_version,
        };
        
        pois.push(poi);
    }
    
    Ok(pois)
}

/// Initialize full navigation dataset from files
pub fn load_navigation_data(poi_path: &str, container_path: &str) -> Result<(Vec<PointOfInterest>, Vec<ObjectContainer>), DataLoadError> {
    let containers = load_containers(container_path)?;
    let pois = load_pois(poi_path)?;
    
    Ok((pois, containers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    #[test]
    fn test_load_containers() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_containers.json");
        
        // Create a test JSON file
        let test_json = r#"[
            {
                "id": 1,
                "system": "Stanton",
                "cont_type": "Planet",
                "name": "Hurston",
                "internal_name": "Stanton1",
                "pos_x": 12875442280.0,
                "pos_y": 0.0,
                "pos_z": 0.0,
                "rot_vel_x": 5.0,
                "rot_vel_y": 0.0,
                "rot_vel_z": 0.0,
                "rot_adj_x": 0.0,
                "rot_adj_y": 0.0,
                "rot_adj_z": 0.0,
                "rot_quat_w": 1.0,
                "rot_quat_x": 0.0,
                "rot_quat_y": 0.0,
                "rot_quat_z": 0.0,
                "body_radius": 1000000.0,
                "om_radius": 1500000.0,
                "grid_radius": 2000000.0
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let containers = load_containers(file_path.to_str().unwrap()).unwrap();
        
        // Verify loaded data
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].id, 1);
        assert_eq!(containers[0].name, "Hurston");
        assert_eq!(containers[0].system, System::Stanton);
        assert_eq!(containers[0].container_type, ContainerType::Planet);
        assert_eq!(containers[0].position.x, 12875442280.0);
    }
    
    #[test]
    fn test_load_pois() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_pois.json");
        
        // Create a test JSON file
        let test_json = r#"[
            {
                "id": 1,
                "name": "Lorville",
                "system": "Stanton",
                "obj_container": "Hurston",
                "poi_type": "LandingZone",
                "class": "City",
                "pos_x": -328.91,
                "pos_y": -785.98,
                "pos_z": 564.17,
                "has_qt_marker": true,
                "date_added": "2020-01-01",
                "with_version": "3.0.0"
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load POIs from the file
        let pois = load_pois(file_path.to_str().unwrap()).unwrap();
        
        // Verify loaded data
        assert_eq!(pois.len(), 1);
        assert_eq!(pois[0].id, 1);
        assert_eq!(pois[0].name, "Lorville");
        assert_eq!(pois[0].system, "Stanton");
        assert_eq!(pois[0].obj_container, Some("Hurston".to_string()));
        assert_eq!(pois[0].poi_type, PoiType::LandingZone);
        assert_eq!(pois[0].position.x, -328.91);
        assert_eq!(pois[0].position.y, -785.98);
        assert_eq!(pois[0].position.z, 564.17);
    }
}
