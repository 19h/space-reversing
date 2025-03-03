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
pub struct SerializedContainer {
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
pub struct SerializedPoi {
    pub id: u32,
    pub name: String,
    pub system: String,
    #[serde(default)]
    pub obj_container: Option<String>,
    pub poi_type: String,
    pub class: String,
    pub pos_x: f64,
    pub pos_y: f64,
    pub pos_z: f64,
    pub has_qt_marker: bool,
    #[serde(default)]
    pub date_added: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub with_version: Option<String>,
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

/// Load celestial object containers from JSON bytes
pub fn load_containers_from_bytes(data: &[u8]) -> Result<Vec<ObjectContainer>, DataLoadError> {
    // Parse JSON
    let serialized_containers: Vec<SerializedContainer> = serde_json::from_slice(data)?;
    
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

/// Load celestial object containers from JSON file
pub fn load_containers(path: &str) -> Result<Vec<ObjectContainer>, DataLoadError> {
    // Read file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    
    // Use the byte-based loader
    load_containers_from_bytes(&buffer)
}

/// Load points of interest from JSON bytes
pub fn load_pois_from_bytes(data: &[u8]) -> Result<Vec<PointOfInterest>, DataLoadError> {
    // Parse JSON
    let serialized_pois: Vec<SerializedPoi> = serde_json::from_slice(data)?;
    
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
            system: System::from_str(&sp.system).unwrap_or(System::Stanton),
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

/// Load points of interest from JSON file
pub fn load_pois(path: &str) -> Result<Vec<PointOfInterest>, DataLoadError> {
    // Read file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    
    // Use the byte-based loader
    load_pois_from_bytes(&buffer)
}

/// Initialize full navigation dataset from files
pub fn load_navigation_data(poi_path: &str, container_path: &str) -> Result<(Vec<PointOfInterest>, Vec<ObjectContainer>), DataLoadError> {
    let containers = load_containers(container_path)?;
    let pois = load_pois(poi_path)?;
    
    Ok((pois, containers))
}

/// Initialize full navigation dataset from bytes
pub fn load_navigation_data_from_bytes(poi_data: &[u8], container_data: &[u8]) -> Result<(Vec<PointOfInterest>, Vec<ObjectContainer>), DataLoadError> {
    let containers = load_containers_from_bytes(container_data)?;
    let pois = load_pois_from_bytes(poi_data)?;
    
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
        assert_eq!(pois[0].system, System::Stanton);
        assert_eq!(pois[0].obj_container, Some("Hurston".to_string()));
        assert_eq!(pois[0].poi_type, PoiType::LandingZone);
        assert_eq!(pois[0].position.x, -328.91);
        assert_eq!(pois[0].position.y, -785.98);
        assert_eq!(pois[0].position.z, 564.17);
    }
    
    #[test]
    fn test_load_multiple_containers() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("multi_containers.json");
        
        // Create a test JSON file with multiple containers
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
            },
            {
                "id": 2,
                "system": "Stanton",
                "cont_type": "Moon",
                "name": "Arial",
                "internal_name": "Stanton1a",
                "pos_x": 12875442280.0,
                "pos_y": 1000000.0,
                "pos_z": 0.0,
                "rot_vel_x": 10.0,
                "rot_vel_y": 0.0,
                "rot_vel_z": 0.0,
                "rot_adj_x": 0.0,
                "rot_adj_y": 0.0,
                "rot_adj_z": 0.0,
                "rot_quat_w": 1.0,
                "rot_quat_x": 0.0,
                "rot_quat_y": 0.0,
                "rot_quat_z": 0.0,
                "body_radius": 200000.0,
                "om_radius": 300000.0,
                "grid_radius": 400000.0
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let containers = load_containers(file_path.to_str().unwrap()).unwrap();
        
        // Verify loaded data
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].id, 1);
        assert_eq!(containers[0].name, "Hurston");
        assert_eq!(containers[0].container_type, ContainerType::Planet);
        
        assert_eq!(containers[1].id, 2);
        assert_eq!(containers[1].name, "Arial");
        assert_eq!(containers[1].container_type, ContainerType::Moon);
        assert_eq!(containers[1].position.y, 1000000.0);
        assert_eq!(containers[1].body_radius, 200000.0);
    }
    
    #[test]
    fn test_load_empty_containers() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("empty_containers.json");
        
        // Create an empty array JSON file
        let test_json = r#"[]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let containers = load_containers(file_path.to_str().unwrap()).unwrap();
        
        // Verify loaded data is empty
        assert!(containers.is_empty());
    }
    
    #[test]
    fn test_load_invalid_json_containers() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("invalid_containers.json");
        
        // Create an invalid JSON file
        let test_json = r#"[{"id": 1, "invalid": true]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let result = load_containers(file_path.to_str().unwrap());
        
        // Verify error
        assert!(result.is_err());
        if let Err(DataLoadError::JsonError(_)) = result {
            // This is the expected error type
        } else {
            panic!("Expected JsonError, got different error: {:?}", result);
        }
    }
    
    #[test]
    fn test_load_container_with_unknown_system() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("unknown_system.json");
        
        // Create a test JSON file with unknown system
        let test_json = r#"[
            {
                "id": 1,
                "system": "UnknownSystem",
                "cont_type": "Planet",
                "name": "TestPlanet",
                "internal_name": "Test1",
                "pos_x": 0.0,
                "pos_y": 0.0,
                "pos_z": 0.0,
                "rot_vel_x": 0.0,
                "rot_vel_y": 0.0,
                "rot_vel_z": 0.0,
                "rot_adj_x": 0.0,
                "rot_adj_y": 0.0,
                "rot_adj_z": 0.0,
                "rot_quat_w": 1.0,
                "rot_quat_x": 0.0,
                "rot_quat_y": 0.0,
                "rot_quat_z": 0.0,
                "body_radius": 1000.0,
                "om_radius": 1500.0,
                "grid_radius": 2000.0
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let result = load_containers(file_path.to_str().unwrap());
        
        // Verify error
        assert!(result.is_err());
        if let Err(DataLoadError::ParseError(msg)) = &result {
            assert!(msg.contains("Unknown system"));
        } else {
            panic!("Expected ParseError for unknown system, got: {:?}", result);
        }
    }
    
    #[test]
    fn test_load_container_with_unknown_type() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("unknown_type.json");
        
        // Create a test JSON file with unknown container type
        let test_json = r#"[
            {
                "id": 1,
                "system": "Stanton",
                "cont_type": "UnknownType",
                "name": "TestObject",
                "internal_name": "Test1",
                "pos_x": 0.0,
                "pos_y": 0.0,
                "pos_z": 0.0,
                "rot_vel_x": 0.0,
                "rot_vel_y": 0.0,
                "rot_vel_z": 0.0,
                "rot_adj_x": 0.0,
                "rot_adj_y": 0.0,
                "rot_adj_z": 0.0,
                "rot_quat_w": 1.0,
                "rot_quat_x": 0.0,
                "rot_quat_y": 0.0,
                "rot_quat_z": 0.0,
                "body_radius": 1000.0,
                "om_radius": 1500.0,
                "grid_radius": 2000.0
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load containers from the file
        let result = load_containers(file_path.to_str().unwrap());
        
        // Verify error
        assert!(result.is_err());
        if let Err(DataLoadError::ParseError(msg)) = &result {
            assert!(msg.contains("Unknown container type"));
        } else {
            panic!("Expected ParseError for unknown container type, got: {:?}", result);
        }
    }
    
    #[test]
    fn test_load_multiple_pois() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("multi_pois.json");
        
        // Create a test JSON file with multiple POIs
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
            },
            {
                "id": 2,
                "name": "Aberdeen Mining Facility",
                "system": "Stanton",
                "obj_container": "Aberdeen",
                "poi_type": "Outpost",
                "class": "Outpost",
                "pos_x": 100.0,
                "pos_y": 200.0,
                "pos_z": 300.0,
                "has_qt_marker": false,
                "comment": "Test comment"
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load POIs from the file
        let pois = load_pois(file_path.to_str().unwrap()).unwrap();
        
        // Verify loaded data
        assert_eq!(pois.len(), 2);
        assert_eq!(pois[0].id, 1);
        assert_eq!(pois[0].name, "Lorville");
        assert_eq!(pois[0].poi_type, PoiType::LandingZone);
        
        assert_eq!(pois[1].id, 2);
        assert_eq!(pois[1].name, "Aberdeen Mining Facility");
        assert_eq!(pois[1].obj_container, Some("Aberdeen".to_string()));
        assert_eq!(pois[1].poi_type, PoiType::Outpost);
        assert_eq!(pois[1].comment, Some("Test comment".to_string()));
    }
    
    #[test]
    fn test_load_poi_with_unknown_poi_type() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("unknown_poi_type.json");
        
        // Create a test JSON file with unknown POI type
        let test_json = r#"[
            {
                "id": 1,
                "name": "Test POI",
                "system": "Stanton",
                "obj_container": "Hurston",
                "poi_type": "UnknownPoiType",
                "class": "Other",
                "pos_x": 0.0,
                "pos_y": 0.0,
                "pos_z": 0.0,
                "has_qt_marker": false
            }
        ]"#;
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_json.as_bytes()).unwrap();
        
        // Load POIs from the file
        let result = load_pois(file_path.to_str().unwrap());
        
        // Verify error
        assert!(result.is_err());
        if let Err(DataLoadError::ParseError(msg)) = &result {
            assert!(msg.contains("Unknown POI type"));
        } else {
            panic!("Expected ParseError for unknown POI type, got: {:?}", result);
        }
    }
    
    #[test]
    fn test_load_containers_from_bytes() {
        // Create a test JSON
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
        
        // Load containers directly from bytes
        let containers = load_containers_from_bytes(test_json.as_bytes()).unwrap();
        
        // Verify loaded data
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].id, 1);
        assert_eq!(containers[0].name, "Hurston");
        assert_eq!(containers[0].system, System::Stanton);
        assert_eq!(containers[0].container_type, ContainerType::Planet);
    }
    
    #[test]
    fn test_load_pois_from_bytes() {
        // Create a test JSON
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
        
        // Load POIs directly from bytes
        let pois = load_pois_from_bytes(test_json.as_bytes()).unwrap();
        
        // Verify loaded data
        assert_eq!(pois.len(), 1);
        assert_eq!(pois[0].id, 1);
        assert_eq!(pois[0].name, "Lorville");
        assert_eq!(pois[0].system, System::Stanton);
        assert_eq!(pois[0].poi_type, PoiType::LandingZone);
    }
    
    #[test]
    fn test_load_navigation_data() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        let container_path = dir.path().join("test_containers.json");
        let poi_path = dir.path().join("test_pois.json");
        
        // Create container test JSON file
        let container_json = r#"[
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
        
        let poi_json = r#"[
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
                "has_qt_marker": true
            }
        ]"#;
        
        // Write test files
        let mut container_file = File::create(&container_path).unwrap();
        container_file.write_all(container_json.as_bytes()).unwrap();
        
        let mut poi_file = File::create(&poi_path).unwrap();
        poi_file.write_all(poi_json.as_bytes()).unwrap();
        
        // Load navigation data
        let (pois, containers) = load_navigation_data(
            poi_path.to_str().unwrap(),
            container_path.to_str().unwrap()
        ).unwrap();
        
        // Verify data
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "Hurston");
        
        assert_eq!(pois.len(), 1);
        assert_eq!(pois[0].name, "Lorville");
        assert_eq!(pois[0].obj_container, Some("Hurston".to_string()));
    }
    
    #[test]
    fn test_load_navigation_data_from_bytes() {
        // Create test JSONs
        let container_json = r#"[
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
        
        let poi_json = r#"[
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
                "has_qt_marker": true
            }
        ]"#;
        
        // Load navigation data from bytes
        let (pois, containers) = load_navigation_data_from_bytes(
            poi_json.as_bytes(),
            container_json.as_bytes()
        ).unwrap();
        
        // Verify data
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "Hurston");
        
        assert_eq!(pois.len(), 1);
        assert_eq!(pois[0].name, "Lorville");
        assert_eq!(pois[0].obj_container, Some("Hurston".to_string()));
    }
    
    #[test]
    fn test_nonexistent_file() {
        // Try to load a file that doesn't exist
        let result = load_containers("nonexistent_file.json");
        
        // Verify error
        assert!(result.is_err());
        if let Err(DataLoadError::IoError(_)) = result {
            // This is the expected error type
        } else {
            panic!("Expected IoError, got different error: {:?}", result);
        }
    }
}
