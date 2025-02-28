use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::coordinate_transform::{CoordinateTransformer, TransformDirection};
use crate::nav_core::NavigationCore;
use crate::types::{
    AstronomicalDataProvider, ContainerType, EulerAngles, LineOfSightResult, MeetingPoint,
    NamedDistance, NavNode, NavNodeType, NavigationPlan, ObjectContainer, PathComplexity,
    PathPoint, PathSegment, PointOfInterest, SearchDirection, System, TravelType, Vector3,
    VisibilityEdge,
};

/// Advanced navigation planner with bidirectional search and pre-computed visibility
pub struct NavigationPlanner<T: AstronomicalDataProvider> {
    pub core: NavigationCore<T>,
    pub data_provider: Arc<T>,
    pub transformer: CoordinateTransformer,
    
    // Navigation markers
    pub orbital_markers: HashMap<String, Vec<Arc<NavNode>>>,
    pub qt_markers: Vec<Arc<NavNode>>,
    pub all_navigation_nodes: Vec<Arc<NavNode>>,
    
    // Precomputed visibility graph for efficient pathfinding
    pub visibility_graph: HashMap<String, Vec<VisibilityEdge>>,
    
    // Maximum iterations for pathfinding
    pub max_iterations: usize,
    
    // Current position reference frame
    pub origin_container: Option<Arc<ObjectContainer>>,
}

impl<T: AstronomicalDataProvider> NavigationPlanner<T> {
    /// Create a new navigation planner
    pub fn new(data_provider: Arc<T>) -> Self {
        let core = NavigationCore::new(Arc::clone(&data_provider));
        let transformer = CoordinateTransformer::new();
        
        let mut planner = Self {
            core,
            data_provider,
            transformer,
            orbital_markers: HashMap::new(),
            qt_markers: Vec::new(),
            all_navigation_nodes: Vec::new(),
            visibility_graph: HashMap::new(),
            max_iterations: 1000,
            origin_container: None,
        };
        
        // Initialize navigation points and visibility graph
        planner.initialize_navigation_points();
        planner.precompute_visibility_graph();
        
        planner
    }
    
    /// Initialize all navigation points and build the node network
    fn initialize_navigation_points(&mut self) {
        // First, collect all containers that need orbital markers
        let containers_needing_markers: Vec<ObjectContainer> = self.data_provider
            .get_object_containers()
            .iter()
            .filter(|container| {
                container.container_type == ContainerType::Planet || 
                container.container_type == ContainerType::Moon
            })
            .cloned()
            .collect();
        
        // Now generate orbital markers for each container
        for container in &containers_needing_markers {
            self.generate_orbital_markers(container);
        }
        
        // Add quantum travel markers from POIs
        for poi in self.data_provider.get_points_of_interest() {
            if poi.has_qt_marker {
                let qt_node = Arc::new(NavNode::new(
                    self.get_global_coordinates(poi),
                    NavNodeType::QuantumMarker,
                    poi.name.clone(),
                    None,
                ));
                self.qt_markers.push(Arc::clone(&qt_node));
                self.all_navigation_nodes.push(qt_node);
            }
        }
        
        // Add Lagrange points and Jump Points as QT markers
        for container in self.data_provider.get_object_containers() {
            if container.container_type == ContainerType::Lagrange || container.container_type == ContainerType::JumpPoint {
                let container_arc = Arc::new(container.clone());
                let nav_node = Arc::new(NavNode::new(
                    container.position,
                    NavNodeType::QuantumMarker,
                    container.name.clone(),
                    Some(Arc::clone(&container_arc)),
                ));
                self.qt_markers.push(Arc::clone(&nav_node));
                self.all_navigation_nodes.push(nav_node);
            }
        }
        
        log::info!(
            "Initialized {} navigation nodes",
            self.all_navigation_nodes.len()
        );
        log::info!("- {} QT markers", self.qt_markers.len());
        log::info!("- {} celestial bodies with orbital markers", self.orbital_markers.len());
    }
    
    /// Generate orbital markers for a celestial body with optimized positioning
    fn generate_orbital_markers(&mut self, container: &ObjectContainer) {
        let mut markers = Vec::new();
        let radius = container.om_radius;
        let center = container.position;
        let container_arc = Arc::new(container.clone());
        
        // Create the 6 orbital markers positioned around the celestial body
        // OM-1: +z (North Pole)
        let om1 = Arc::new(NavNode::new(
            Vector3::new(center.x, center.y, center.z + radius),
            NavNodeType::OrbitalMarker,
            format!("{} OM-1", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om1));
        
        // OM-2: -z (South Pole)
        let om2 = Arc::new(NavNode::new(
            Vector3::new(center.x, center.y, center.z - radius),
            NavNodeType::OrbitalMarker,
            format!("{} OM-2", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om2));
        
        // OM-3: +y (East)
        let om3 = Arc::new(NavNode::new(
            Vector3::new(center.x, center.y + radius, center.z),
            NavNodeType::OrbitalMarker,
            format!("{} OM-3", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om3));
        
        // OM-4: -y (West)
        let om4 = Arc::new(NavNode::new(
            Vector3::new(center.x, center.y - radius, center.z),
            NavNodeType::OrbitalMarker,
            format!("{} OM-4", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om4));
        
        // OM-5: +x (North)
        let om5 = Arc::new(NavNode::new(
            Vector3::new(center.x + radius, center.y, center.z),
            NavNodeType::OrbitalMarker,
            format!("{} OM-5", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om5));
        
        // OM-6: -x (South)
        let om6 = Arc::new(NavNode::new(
            Vector3::new(center.x - radius, center.y, center.z),
            NavNodeType::OrbitalMarker,
            format!("{} OM-6", container.name),
            Some(Arc::clone(&container_arc)),
        ));
        markers.push(Arc::clone(&om6));
        
        self.orbital_markers.insert(container.name.clone(), markers.clone());
        
        // Add all markers to the complete navigation node list
        for marker in markers {
            self.all_navigation_nodes.push(marker);
        }
    }
    
    /// Precompute visibility graph between all navigation nodes
    fn precompute_visibility_graph(&mut self) {
        // Initialize visibility graph
        for node in &self.all_navigation_nodes {
            self.visibility_graph.insert(self.get_node_key(node), Vec::new());
        }
        
        // Compute visibility with explicit null checks
        for i in 0..self.all_navigation_nodes.len() {
            let from_node = Arc::clone(&self.all_navigation_nodes[i]);
            let from_key = self.get_node_key(&from_node);
            
            for j in i + 1..self.all_navigation_nodes.len() {
                let to_node = Arc::clone(&self.all_navigation_nodes[j]);
                let to_key = self.get_node_key(&to_node);
                
                // Skip orbital markers on the same celestial body
                let same_orbital_markers = match (&from_node.node_type, &to_node.node_type) {
                    (NavNodeType::OrbitalMarker, NavNodeType::OrbitalMarker) => {
                        match (&from_node.container_ref, &to_node.container_ref) {
                            (Some(fc), Some(tc)) => fc.name == tc.name,
                            _ => false,
                        }
                    },
                    _ => false,
                };
                
                if same_orbital_markers {
                    continue;
                }
                
                // Check line of sight
                let los_result = self.check_line_of_sight(&from_node.position, &to_node.position);
                
                // Create bidirectional edges
                let forward_edge = VisibilityEdge {
                    from_node: Arc::clone(&from_node),
                    to_node: Arc::clone(&to_node),
                    distance: from_node.position.distance(&to_node.position),
                    has_los: los_result.has_los,
                    obstruction: los_result.obstruction.clone(),
                };
                
                let backward_edge = VisibilityEdge {
                    from_node: Arc::clone(&to_node),
                    to_node: Arc::clone(&from_node),
                    distance: to_node.position.distance(&from_node.position),
                    has_los: los_result.has_los,
                    obstruction: los_result.obstruction,
                };
                
                // Add edges to the graph
                if let Some(edges) = self.visibility_graph.get_mut(&from_key) {
                    edges.push(forward_edge);
                }
                
                if let Some(edges) = self.visibility_graph.get_mut(&to_key) {
                    edges.push(backward_edge);
                }
            }
        }
        
        log::info!(
            "Precomputed visibility graph with {} nodes",
            self.visibility_graph.len()
        );
    }
    
    /// Generate a unique key for a navigation node for graph operations
    fn get_node_key(&self, node: &NavNode) -> String {
        format!(
            "{}_{:.3}_{:.3}_{:.3}",
            node.node_type, node.position.x, node.position.y, node.position.z
        )
    }
    
    /// Check for line of sight between two points
    fn check_line_of_sight(&self, from: &Vector3, to: &Vector3) -> LineOfSightResult {
        self.core.check_line_of_sight(from, to)
    }
    
    /// Find all visible markers from a specific position using the precomputed visibility graph
    fn find_visible_markers(
        &self,
        position: &Vector3,
        search_type: MarkerSearchType,
    ) -> Vec<(Arc<NavNode>, Option<Arc<ObjectContainer>>)> {
        let mut results = Vec::new();
        
        // Determine which nodes to check based on search type
        let nodes_to_check: Vec<Arc<NavNode>> = match search_type {
            MarkerSearchType::All => self.all_navigation_nodes.clone(),
            MarkerSearchType::Orbital => {
                let mut orbital_nodes = Vec::new();
                for markers in self.orbital_markers.values() {
                    orbital_nodes.extend(markers.iter().cloned());
                }
                orbital_nodes
            },
            MarkerSearchType::QuantumTravel => self.qt_markers.clone(),
        };
        
        // Check visibility to each node
        for node in nodes_to_check {
            let los_result = self.check_line_of_sight(position, &node.position);
            if los_result.has_los {
                results.push((node, None));
            } else {
                // Even if not visible, include with obstruction info for advanced pathfinding
                results.push((node, los_result.obstruction));
            }
        }
        
        results
    }
    
    /// Find visible markers with system boundary enforcement
    fn find_visible_markers_in_system(
        &self,
        position: &Vector3,
        system: System,
        search_type: MarkerSearchType,
    ) -> Vec<(Arc<NavNode>, Option<Arc<ObjectContainer>>)> {
        let all_markers = self.find_visible_markers(position, search_type);
        
        // System-bounded filtration
        all_markers.into_iter().filter(|(node, _)| {
            // Container-based system resolution
            if let Some(container_ref) = &node.container_ref {
                return container_ref.system == system;
            }
            
            // If no container reference, use heuristic matching on name
            if node.name.contains(&system.to_string()) {
                return true;
            }
            
            // For QT markers that might be POIs, find the associated POI and check its system
            if node.node_type == NavNodeType::QuantumMarker {
                if let Some(poi) = self.data_provider.get_point_of_interest_by_name(&node.name) {
                    return poi.system == system.to_string();
                }
            }
            
            false
        }).collect()
    }
    
    /// Bidirectional A* pathfinding algorithm optimized for 3D space navigation
    fn find_path_bidirectional(
        &self,
        start_pos: &Vector3,
        end_pos: &Vector3,
    ) -> Option<Vec<Arc<NavNode>>> {
        // Log navigation parameters
        log::info!("Starting bidirectional pathfinding:");
        log::info!(
            "- Origin: ({:.2}, {:.2}, {:.2})",
            start_pos.x, start_pos.y, start_pos.z
        );
        log::info!(
            "- Destination: ({:.2}, {:.2}, {:.2})",
            end_pos.x, end_pos.y, end_pos.z
        );
        log::info!(
            "- Direct distance: {:.2} km",
            start_pos.distance(end_pos) / 1000.0
        );
        
        // Create start and end nodes
        let start_node = Arc::new(NavNode {
            position: *start_pos,
            parent_node: None,
            g_cost: 0.0,
            h_cost: start_pos.distance(end_pos),
            f_cost: start_pos.distance(end_pos),
            node_type: NavNodeType::Origin,
            name: "Start Position".to_string(),
            container_ref: None,
            obstruction_path: false,
            search_direction: SearchDirection::Forward,
        });
        
        let end_node = Arc::new(NavNode {
            position: *end_pos,
            parent_node: None,
            g_cost: 0.0,
            h_cost: end_pos.distance(start_pos),
            f_cost: end_pos.distance(start_pos),
            node_type: NavNodeType::Destination,
            name: "Destination".to_string(),
            container_ref: None,
            obstruction_path: false,
            search_direction: SearchDirection::Backward,
        });
        
        // Check if there's a direct path
        let los_result = self.check_line_of_sight(start_pos, end_pos);
        if los_result.has_los {
            // Direct path available - no changes needed
            log::info!("Direct path available - no obstructions detected");
            
            // Create the end node with a parent link to the start node
            let end_with_parent = Arc::new(NavNode {
                position: *end_pos,
                parent_node: Some(Arc::clone(&start_node)),
                g_cost: start_pos.distance(end_pos),
                h_cost: 0.0,
                f_cost: start_pos.distance(end_pos),
                node_type: NavNodeType::Destination,
                name: "Destination".to_string(),
                container_ref: None,
                obstruction_path: false,
                search_direction: SearchDirection::Forward,
            });
            
            return Some(vec![start_node, end_with_parent]);
        } else if let Some(obstruction) = los_result.obstruction {
            log::info!("Direct path obstructed by {}", obstruction.name);
            
            // Explicitly handle obstruction with OM waypoints
            // Find the optimal OM for bypassing this obstruction
            let optimal_om = self.find_optimal_orbital_marker(start_pos, end_pos, &obstruction);
            log::info!("Selected {} for obstruction bypass", optimal_om.name);
            
            // Find the orbital marker node in our navigation nodes
            let om_node = self.all_navigation_nodes.iter().find(|&node| {
                node.node_type == NavNodeType::OrbitalMarker && node.name == optimal_om.name
            });
            
            if let Some(om_node) = om_node {
                // Create an explicit path with the OM as an intermediate waypoint
                let om_with_parent = Arc::new(NavNode {
                    position: om_node.position,
                    parent_node: Some(Arc::clone(&start_node)),
                    g_cost: start_pos.distance(&om_node.position),
                    h_cost: om_node.position.distance(end_pos),
                    f_cost: start_pos.distance(&om_node.position) + om_node.position.distance(end_pos),
                    node_type: NavNodeType::OrbitalMarker,
                    name: om_node.name.clone(),
                    container_ref: om_node.container_ref.clone(),
                    obstruction_path: true,
                    search_direction: SearchDirection::Forward,
                });
                
                let end_with_parent = Arc::new(NavNode {
                    position: *end_pos,
                    parent_node: Some(Arc::clone(&om_with_parent)),
                    g_cost: start_pos.distance(&om_node.position) + om_node.position.distance(end_pos),
                    h_cost: 0.0,
                    f_cost: start_pos.distance(&om_node.position) + om_node.position.distance(end_pos),
                    node_type: NavNodeType::Destination,
                    name: "Destination".to_string(),
                    container_ref: None,
                    obstruction_path: false,
                    search_direction: SearchDirection::Forward,
                });
                
                log::info!("Created explicit obstruction bypass route via {}", om_node.name);
                return Some(vec![start_node, om_with_parent, end_with_parent]);
            }
        }
        
        // Initialize open and closed sets for bidirectional search
        let mut forward_open_set: Vec<Arc<NavNode>> = vec![Arc::clone(&start_node)];
        let mut forward_closed_set: Vec<Arc<NavNode>> = Vec::new();
        
        let mut backward_open_set: Vec<Arc<NavNode>> = vec![Arc::clone(&end_node)];
        let mut backward_closed_set: Vec<Arc<NavNode>> = Vec::new();
        
        // Tracking the best connection point between forward and backward searches
        let mut best_meeting_point: Option<MeetingPoint> = None;
        
        // Find visible markers from start and end
        log::info!("Finding visible navigation markers...");
        let visible_from_start = self.find_visible_markers(start_pos, MarkerSearchType::All);
        let visible_from_end = self.find_visible_markers(end_pos, MarkerSearchType::All);
        
        log::info!("- {} markers visible from start", visible_from_start.len());
        log::info!("- {} markers visible from destination", visible_from_end.len());
        
        // Add visible markers to the open sets
        for (node, obstruction) in visible_from_start {
            let new_node = Arc::new(NavNode {
                position: node.position,
                parent_node: Some(Arc::clone(&start_node)),
                g_cost: start_pos.distance(&node.position),
                h_cost: node.position.distance(end_pos),
                f_cost: start_pos.distance(&node.position) + node.position.distance(end_pos),
                node_type: node.node_type,
                name: node.name.clone(),
                container_ref: node.container_ref.clone(),
                obstruction_path: obstruction.is_some(),
                search_direction: SearchDirection::Forward,
            });
            forward_open_set.push(new_node);
        }
        
        for (node, obstruction) in visible_from_end {
            let new_node = Arc::new(NavNode {
                position: node.position,
                parent_node: Some(Arc::clone(&end_node)),
                g_cost: end_pos.distance(&node.position),
                h_cost: node.position.distance(start_pos),
                f_cost: end_pos.distance(&node.position) + node.position.distance(start_pos),
                node_type: node.node_type,
                name: node.name.clone(),
                container_ref: node.container_ref.clone(),
                obstruction_path: obstruction.is_some(),
                search_direction: SearchDirection::Backward,
            });
            backward_open_set.push(new_node);
        }
        
        // Maximum iterations tracker
        let mut iterations = 0;
        
        // Bidirectional A* algorithm
        log::info!("Starting bidirectional A* search...");
        while !forward_open_set.is_empty() && !backward_open_set.is_empty() {
            iterations += 1;
            if iterations > self.max_iterations {
                log::warn!("Reached maximum iterations ({}) - stopping search", self.max_iterations);
                break;
            }
            
            // Process forward search
            self.process_search_direction(
                &mut forward_open_set,
                &mut forward_closed_set,
                &backward_closed_set,
                SearchDirection::Forward,
                &mut best_meeting_point,
                end_pos,
            );
            
            // Process backward search
            self.process_search_direction(
                &mut backward_open_set,
                &mut backward_closed_set,
                &forward_closed_set,
                SearchDirection::Backward,
                &mut best_meeting_point,
                start_pos,
            );
            
            // Check if we've found a meeting point
            if best_meeting_point.is_some() {
                log::info!("Found optimal path after {} iterations", iterations);
                // Reconstruct the bidirectional path
                return Some(self.reconstruct_bidirectional_path(
                    &best_meeting_point.unwrap()
                ));
            }
        }
        
        // If we reach here, no path was found
        // Check if the search at least made progress and try to construct a partial path
        if let Some(meeting_point) = best_meeting_point {
            log::info!("Found suboptimal path after {} iterations", iterations);
            return Some(self.reconstruct_bidirectional_path(&meeting_point));
        }
        
        log::error!("No path found after {} iterations", iterations);
        None
    }
    
    /// Process one iteration of search in the specified direction
    fn process_search_direction(
        &self,
        open_set: &mut Vec<Arc<NavNode>>,
        closed_set: &mut Vec<Arc<NavNode>>,
        opposite_closed_set: &[Arc<NavNode>],
        direction: SearchDirection,
        best_meeting_point: &mut Option<MeetingPoint>,
        target_pos: &Vector3,
    ) {
        if open_set.is_empty() {
            return;
        }
        
        // Sort open set by fCost ascending
        open_set.sort_by(|a, b| {
            a.f_cost.partial_cmp(&b.f_cost).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Get the node with the lowest fCost
        let current_node = Arc::clone(&open_set.remove(0));
        
        // Move the current node to the closed set
        closed_set.push(Arc::clone(&current_node));
        
        // Check for intersection with the opposite search direction
        for opposite_node in opposite_closed_set {
            // Check if we can connect these nodes (direct line of sight)
            let los_result = self.check_line_of_sight(&current_node.position, &opposite_node.position);
            
            if los_result.has_los {
                // Calculate the total cost of this potential path
                let total_cost = current_node.g_cost +
                    opposite_node.g_cost +
                    current_node.position.distance(&opposite_node.position);
                
                // Update best meeting point if this is better
                let should_update = match best_meeting_point {
                    None => true,
                    Some(mp) => total_cost < mp.total_cost
                };
                
                if should_update {
                    *best_meeting_point = Some(MeetingPoint {
                        forward_node: if direction == SearchDirection::Forward {
                            Arc::clone(&current_node)
                        } else {
                            Arc::clone(opposite_node)
                        },
                        backward_node: if direction == SearchDirection::Backward {
                            Arc::clone(&current_node)
                        } else {
                            Arc::clone(opposite_node)
                        },
                        total_cost,
                    });
                }
            }
        }
        
        // Find neighbors using the visibility graph
        let node_key = self.get_node_key(&current_node);
        let visible_neighbors = match self.visibility_graph.get(&node_key) {
            Some(edges) => edges,
            None => return, // No neighbors found in visibility graph
        };
        
        for edge in visible_neighbors {
            // Skip if not a valid connection
            if !edge.has_los {
                continue;
            }
            
            // Skip if neighbor is in closed set
            if closed_set.iter().any(|node| node.equals(&edge.to_node)) {
                continue;
            }
            
            // Calculate tentative gCost
            let tentative_g_cost = current_node.g_cost + edge.distance;
            
            // Check if neighbor is in open set - store index instead of reference
            let neighbor_idx = open_set.iter().position(|node| node.equals(&edge.to_node));
            
            match neighbor_idx {
                None => {
                    // Create a new node with current as parent
                    let h_cost = match (direction, &*best_meeting_point) {
                        (SearchDirection::Forward, Some(mp)) => {
                            edge.to_node.position.distance(&mp.backward_node.position)
                        }
                        (SearchDirection::Backward, Some(mp)) => {
                            edge.to_node.position.distance(&mp.forward_node.position)
                        }
                        _ => {
                            // No meeting point yet, use target position
                            edge.to_node.position.distance(target_pos)
                        }
                    };
                    
                    let new_node = Arc::new(NavNode {
                        position: edge.to_node.position,
                        parent_node: Some(Arc::clone(&current_node)),
                        g_cost: tentative_g_cost,
                        h_cost,
                        f_cost: tentative_g_cost + h_cost,
                        node_type: edge.to_node.node_type,
                        name: edge.to_node.name.clone(),
                        container_ref: edge.to_node.container_ref.clone(),
                        obstruction_path: edge.to_node.obstruction_path,
                        search_direction: direction,
                    });
                    
                    open_set.push(new_node);
                }
                Some(pos) => {
                    // Get the existing node
                    let neighbor = &open_set[pos];
                    
                    // Check if this path is better than the previous one
                    if tentative_g_cost < neighbor.g_cost {
                        // Update node without using iter_mut().find()
                        let updated_node = Arc::new(NavNode {
                            position: neighbor.position,
                            parent_node: Some(Arc::clone(&current_node)), // Update parent
                            g_cost: tentative_g_cost,
                            h_cost: neighbor.h_cost,
                            f_cost: tentative_g_cost + neighbor.h_cost,
                            node_type: neighbor.node_type,
                            name: neighbor.name.clone(),
                            container_ref: neighbor.container_ref.clone(),
                            obstruction_path: neighbor.obstruction_path,
                            search_direction: neighbor.search_direction,
                        });
                        
                        // Remove and replace in open set
                        open_set.remove(pos);
                        open_set.push(updated_node);
                    }
                }
            }
        }
    }
    
    /// Reconstruct a bidirectional path by joining forward and backward paths
    fn reconstruct_bidirectional_path(&self, meeting_point: &MeetingPoint) -> Vec<Arc<NavNode>> {
        // Reconstruct the forward path
        let mut forward_path = Vec::new();
        let mut current_node = Some(Arc::clone(&meeting_point.forward_node));
        
        while let Some(node) = current_node {
            forward_path.push(Arc::clone(&node));
            current_node = node.parent_node.clone();
        }
        
        // Reverse to get correct order (start to meeting point)
        forward_path.reverse();
        
        // Reconstruct the backward path
        let mut backward_path = Vec::new();
        let mut current_node = Some(Arc::clone(&meeting_point.backward_node));
        
        while let Some(node) = current_node {
            if node.parent_node.is_some() { // Skip the backward destination node
                backward_path.push(Arc::clone(&node));
            }
            current_node = node.parent_node.clone();
        }
        
        // Join the paths (forward path + backward path in reverse)
        let mut complete_path = forward_path;
        
        // Add the backward path in reverse order
        for node in backward_path.iter().rev() {
            // Create a new node with parent pointing to previous node in joined path
            let parent = Arc::clone(complete_path.last().unwrap());
            let new_node = Arc::new(NavNode {
                position: node.position,
                parent_node: Some(parent),
                g_cost: node.g_cost,
                h_cost: node.h_cost,
                f_cost: node.f_cost,
                node_type: node.node_type,
                name: node.name.clone(),
                container_ref: node.container_ref.clone(),
                obstruction_path: node.obstruction_path,
                search_direction: SearchDirection::Forward, // Convert to forward
            });
            
            complete_path.push(new_node);
        }
        
        // Add final destination node
        let parent = Arc::clone(complete_path.last().unwrap());
        let dest_node = Arc::new(NavNode {
            position: meeting_point.backward_node.position,
            parent_node: Some(parent),
            g_cost: meeting_point.total_cost,
            h_cost: 0.0,
            f_cost: meeting_point.total_cost,
            node_type: NavNodeType::Destination,
            name: "Destination".to_string(),
            container_ref: None,
            obstruction_path: false,
            search_direction: SearchDirection::Forward,
        });
        
        complete_path.push(dest_node);
        
        log::info!("Reconstructed path with {} nodes", complete_path.len());
        complete_path
    }
    
    /// Calculate travel time with realistic acceleration/deceleration curves
    fn calculate_travel_time(&self, distance: f64, travel_type: TravelType) -> f64 {
        match travel_type {
            TravelType::Quantum => {
                // Quantum travel velocity ~ 20% speed of light
                let speed_of_light = 299792458.0; // m/s
                let quantum_speed = speed_of_light * 0.2; // m/s
                
                // Add acceleration/deceleration time (approximately 10 seconds each)
                let cruise_time = distance / quantum_speed;
                let transition_time = 20.0; // seconds
                
                cruise_time + transition_time
            }
            TravelType::Sublight => {
                // Sublight travel with acceleration model
                // Max speed ~ 1,000 m/s, acceleration ~ 50 m/s²
                let max_speed = 1000.0; // m/s
                let acceleration = 50.0; // m/s²
                
                // Time to reach full speed
                let time_to_max_speed: f64 = max_speed / acceleration;
                
                // Distance covered during acceleration/deceleration
                let accel_distance = 0.5 * acceleration * time_to_max_speed.powi(2);
                
                // Check if we have enough distance to reach max speed
                if distance <= accel_distance * 2.0 {
                    // Short distance - triangular velocity profile
                    let peak_time = (distance / acceleration).sqrt();
                    peak_time * 2.0
                } else {
                    // Long distance - trapezoidal velocity profile
                    let cruise_distance = distance - (accel_distance * 2.0);
                    let cruise_time = cruise_distance / max_speed;
                    (time_to_max_speed * 2.0) + cruise_time
                }
            }
        }
    }
    
    /// Create a detailed navigation plan from the path
    fn create_navigation_plan(&self, path: &[Arc<NavNode>]) -> NavigationPlan {
        let mut segments = Vec::new();
        let mut total_distance = 0.0;
        let mut total_estimated_time = 0.0;
        let mut quantum_jumps = 0;
        let mut obstructions = HashSet::new();
        
        for i in 0..path.len() - 1 {
            let from = &path[i];
            let to = &path[i + 1];
            
            let distance = from.position.distance(&to.position);
            
            // Determine travel type based on distance and node types
            let use_sublight =
                from.node_type == NavNodeType::OrbitalMarker || to.node_type == NavNodeType::OrbitalMarker
                || distance <= 20000.0;
            
            let travel_type = if use_sublight {
                TravelType::Sublight
            } else {
                TravelType::Quantum
            };
            
            // Calculate estimated time
            let estimated_time = self.calculate_travel_time(distance, travel_type);
            
            // Calculate direction
            let direction = self.calculate_euler_angles(&from.position, &to.position);
            
            // Check for obstructions in this segment
            let los_result = self.check_line_of_sight(&from.position, &to.position);
            
            // Add obstruction to the list if found
            if let Some(obstruction) = &los_result.obstruction {
                obstructions.insert(obstruction.name.clone());
            }
            
            // Determine if this segment is part of an obstruction bypass
            let is_obstruction_bypass = from.obstruction_path || to.obstruction_path;
            
            // Create segment
            let segment = PathSegment {
                from: PathPoint {
                    name: from.name.clone(),
                    position: from.position,
                    point_type: from.node_type,
                },
                to: PathPoint {
                    name: to.name.clone(),
                    position: to.position,
                    point_type: to.node_type,
                },
                distance,
                travel_type,
                estimated_time,
                direction,
                obstruction: los_result.obstruction.map(|o| o.name.clone()),
                is_obstruction_bypass,
            };
            
            segments.push(segment);
            total_distance += distance;
            total_estimated_time += estimated_time;
            
            if travel_type == TravelType::Quantum {
                quantum_jumps += 1;
            }
        }
        
        // Determine path complexity
        let path_complexity = if path.len() == 2 {
            PathComplexity::Direct
        } else if path.len() <= 4 {
            PathComplexity::Simple
        } else {
            PathComplexity::Complex
        };
        
        NavigationPlan {
            segments,
            total_distance,
            total_estimated_time,
            quantum_jumps,
            obstruction_detected: !obstructions.is_empty(),
            obstructions: obstructions.into_iter().collect(),
            path_complexity,
            origin_container: self.origin_container.clone(),
        }
    }
    
    /// Set current position using local coordinates relative to an object container
    pub fn set_position_local(&mut self, container_name: &str, local_x: f64, local_y: f64, local_z: f64) {
        let container_opt = self.data_provider.get_object_container_by_name(container_name);
        
        let container = match container_opt {
            Some(c) => c,
            None => {
                log::error!("Container {} not found", container_name);
                return;
            }
        };
        
        // Store reference to origin container for contextual navigation
        self.origin_container = Some(Arc::new(container.clone()));
        
        // Transform local coordinates (in km) to global coordinates (in m)
        let local_position = Vector3::new(local_x, local_y, local_z);
        let global_pos = self.transformer.transform_coordinates(
            &local_position,
            container,
            TransformDirection::ToGlobal,
        );
        
        // Update position with global coordinates
        self.update_position(global_pos.x, global_pos.y, global_pos.z);
        
        // Log position information
        log::info!(
            "Position set: {} local ({:.3}km, {:.3}km, {:.3}km)",
            container_name, local_x, local_y, local_z
        );
        log::info!(
            "Global position: ({:.2}, {:.2}, {:.2})",
            global_pos.x, global_pos.y, global_pos.z
        );
        
        // Log nearby POIs for context
        let nearby_pois = self.find_nearby_pois(5);
        if !nearby_pois.is_empty() {
            log::info!("Nearby references:");
            for poi in nearby_pois {
                log::info!("- {}: {:.2}km", poi.name, poi.distance);
            }
        }
    }
    
    /// Update position and resolve to nearest container
    pub fn update_position(&mut self, x: f64, y: f64, z: f64) {
        self.core.update_position(x, y, z);
        
        // Update origin container if not set
        if self.origin_container.is_none() {
            if let Some(container) = self.core.get_current_object_container() {
                self.origin_container = Some(Arc::new(container.clone()));
            }
        }
    }
    
    /// Find nearby Points of Interest for contextual awareness
    pub fn find_nearby_pois(&self, limit: usize) -> Vec<NamedDistance> {
        self.core.find_nearby_pois(limit)
    }
    
    /// Calculate Euler angles for direction from current position to destination
    fn calculate_euler_angles(&self, current: &Vector3, destination: &Vector3) -> EulerAngles {
        // Calculate deltas between current and destination positions
        let dx = destination.x - current.x;
        let dy = destination.y - current.y;
        let dz = destination.z - current.z;
        
        // Calculate distance in the XY plane
        let distance_xy = (dx * dx + dy * dy).sqrt();
        
        // Calculate pitch (vertical angle)
        let pitch = (dz / distance_xy).atan() * (180.0 / std::f64::consts::PI);
        
        // Roll is 0 for simplicity
        let roll = 0.0;
        
        // Calculate yaw (horizontal angle)
        let mut yaw = (dy / dx).atan() * (180.0 / std::f64::consts::PI);
        
        // Convert to game's coordinate system
        if yaw > 90.0 {
            yaw = yaw - 270.0;
        } else {
            yaw = yaw + 90.0;
        }
        
        EulerAngles::new(pitch, yaw, roll)
    }
    
    /// Find the optimal orbital marker to navigate around an obstruction
    fn find_optimal_orbital_marker(
        &self,
        start: &Vector3,
        end: &Vector3,
        obstruction: &ObjectContainer,
    ) -> OptimalMarker {
        // Get all orbital markers for this body
        let markers = match self.orbital_markers.get(&obstruction.name) {
            Some(m) => m,
            None => {
                // Fallback if no markers found
                log::warn!("No orbital markers found for {}", obstruction.name);
                return OptimalMarker {
                    name: format!("{} vicinity", obstruction.name),
                    position: Vector3::new(
                        obstruction.position.x + obstruction.om_radius,
                        obstruction.position.y,
                        obstruction.position.z,
                    ),
                };
            }
        };
        
        // Calculate vectors
        let start_to_obstruction = Vector3::new(
            obstruction.position.x - start.x,
            obstruction.position.y - start.y,
            obstruction.position.z - start.z,
        );
        
        let obstruction_to_end = Vector3::new(
            end.x - obstruction.position.x,
            end.y - obstruction.position.y,
            end.z - obstruction.position.z,
        );
        
        // Initialize with first marker
        let mut best_marker = &markers[0];
        let mut best_score = f64::NEG_INFINITY;
        
        // Normalize vectors
        let start_mag = (
            start_to_obstruction.x.powi(2) +
            start_to_obstruction.y.powi(2) +
            start_to_obstruction.z.powi(2)
        ).sqrt();
        
        let end_mag = (
            obstruction_to_end.x.powi(2) +
            obstruction_to_end.y.powi(2) +
            obstruction_to_end.z.powi(2)
        ).sqrt();
        
        let normalized1 = Vector3::new(
            start_to_obstruction.x / start_mag,
            start_to_obstruction.y / start_mag,
            start_to_obstruction.z / start_mag,
        );
        
        let normalized2 = Vector3::new(
            obstruction_to_end.x / end_mag,
            obstruction_to_end.y / end_mag,
            obstruction_to_end.z / end_mag,
        );
        
        // Calculate cross product to determine optimal orbital plane
        let cross_product = Vector3::new(
            normalized1.y * normalized2.z - normalized1.z * normalized2.y,
            normalized1.z * normalized2.x - normalized1.x * normalized2.z,
            normalized1.x * normalized2.y - normalized1.y * normalized2.x,
        );
        
        for marker in markers {
            // Get marker vector from obstruction center
            let marker_vector = Vector3::new(
                marker.position.x - obstruction.position.x,
                marker.position.y - obstruction.position.y,
                marker.position.z - obstruction.position.z,
            );
            
            // Calculate dot product with cross product to find alignment
            let alignment_score =
                marker_vector.x * cross_product.x +
                marker_vector.y * cross_product.y +
                marker_vector.z * cross_product.z;
            
            if alignment_score.abs() > best_score.abs() {
                best_score = alignment_score;
                best_marker = marker;
            }
        }
        
        OptimalMarker {
            name: best_marker.name.clone(),
            position: best_marker.position,
        }
    }
    
    /// Find the parent planet of a moon
    fn find_parent_planet(
        &self,
        moon: &ObjectContainer,
        planets: &[ObjectContainer],
    ) -> Option<Arc<ObjectContainer>> {
        // Only process if this is actually a moon
        if moon.container_type != ContainerType::Moon {
            return None;
        }
        
        // Get all planets in the same system
        let system_planets: Vec<Arc<ObjectContainer>> = planets
            .iter()
            .filter(|p| p.container_type == ContainerType::Planet && p.system == moon.system)
            .map(|p| Arc::new(p.clone()))
            .collect();
        
        if system_planets.is_empty() {
            return None;
        }
        
        // Try to infer parent planet from naming patterns
        let moon_name = moon.name.to_lowercase();
        
        for planet in &system_planets {
            let planet_name = planet.name.to_lowercase();
            
            // Check if moon name contains planet name
            if moon_name.contains(&planet_name) {
                log::info!(
                    "Matched {} to parent planet {} by name",
                    moon.name, planet.name
                );
                return Some(Arc::clone(planet));
            }
        }
        
        // If name-based inference failed, use reference data
        // This is a hard-coded mapping for known moons
        let known_moon_parents: HashMap<&str, &str> = [
            ("Cellin", "Crusader"),
            ("Daymar", "Crusader"),
            ("Yela", "Crusader"),
            ("Aberdeen", "Hurston"),
            ("Arial", "Hurston"),
            ("Ita", "Hurston"),
            ("Magda", "Hurston"),
            ("Clio", "Microtech"),
            ("Calliope", "Microtech"),
            ("Euterpe", "Microtech"),
            ("Lyria", "ArcCorp"),
            ("Wala", "ArcCorp"),
        ].iter().cloned().collect();
        
        if let Some(parent_name) = known_moon_parents.get(moon.name.as_str()) {
            if let Some(parent) = system_planets.iter().find(|p| p.name == *parent_name) {
                log::info!(
                    "Matched {} to parent planet {} by reference data",
                    moon.name, parent.name
                );
                return Some(Arc::clone(parent));
            }
        }
        
        // Default to closest planet by distance
        let mut closest_planet = None;
        let mut min_distance = f64::MAX;
        
        for planet in &system_planets {
            let distance = (
                (moon.position.x - planet.position.x).powi(2) +
                (moon.position.y - planet.position.y).powi(2) +
                (moon.position.z - planet.position.z).powi(2)
            ).sqrt();
            
            if distance < min_distance {
                min_distance = distance;
                closest_planet = Some(Arc::clone(planet));
            }
        }
        
        if let Some(ref planet) = closest_planet {
            log::info!(
                "Matched {} to parent planet {} by proximity",
                moon.name, planet.name
            );
        }
        
        closest_planet
    }
    
    /// Determines if a destination requires going through its parent planet first
    fn requires_planetary_intercept(
        &self,
        destination: &DestinationEntity,
        current_container: Option<&ObjectContainer>,
    ) -> PlanetaryInterceptResult {
        log::info!("Analyzing planetary hierarchy:");
        
        // Log current container info
        if let Some(current) = current_container {
            log::info!("- Current: {} ({:?})", current.name, current.container_type);
            
            // Find current parent if applicable
            let containers = self.data_provider.get_object_containers();
            
            let current_parent_planet = if current.container_type == ContainerType::Moon {
                self.find_parent_planet(current, containers)
            } else if current.container_type == ContainerType::Planet {
                Some(Arc::new(current.clone()))
            } else {
                None
            };
            
            if let Some(ref parent) = current_parent_planet {
                log::info!("  Parent: {}", parent.name);
            }
        } else {
            log::info!("- Current: None (open space)");
        }
        
        // Get destination container reference
        let dest_container = match destination {
            DestinationEntity::Poi(poi) => {
                poi.obj_container.as_ref().and_then(|name| {
                    self.data_provider.get_object_container_by_name(name)
                }).map(|c| Arc::new(c.clone()))
            },
            DestinationEntity::Container(container) => Some(Arc::clone(container)),
        };
        
        log::info!(
            "- Destination: {} ({})",
            dest_container.as_ref().map_or("None", |c| c.name.as_str()),
            &dest_container.as_ref().map_or("None".to_string(), |c| format!("{:?}", c.container_type)),
        );
        
        // If we're already at the correct container, no intercept needed
        if let (Some(current), Some(dest)) = (current_container, &dest_container) {
            if current.name == dest.name {
                log::info!("No intercept needed: Already at destination container");
                return PlanetaryInterceptResult {
                    required: false,
                    parent_container: None,
                };
            }
        }
        
        // If no current container, we're in open space
        if current_container.is_none() {
            // If destination is on a planet/moon, we need to go there first
            if let Some(dest) = &dest_container {
                if dest.container_type == ContainerType::Moon {
                    // For moons, we should go to parent planet first
                    let containers = self.data_provider.get_object_containers();
                    if let Some(dest_parent_planet) = self.find_parent_planet(dest, containers) {
                        log::info!("  Parent: {}", dest_parent_planet.name);
                        log::info!("Planetary intercept required: Must approach {} first", dest_parent_planet.name);
                        return PlanetaryInterceptResult {
                            required: true,
                            parent_container: Some(dest_parent_planet),
                        };
                    }
                }
                
                // For planets or moons without identified parents, go directly
                log::info!("Planetary intercept required: Direct approach to {}", dest.name);
                return PlanetaryInterceptResult {
                    required: true,
                    parent_container: Some(Arc::clone(dest)),
                };
            }
            
            return PlanetaryInterceptResult {
                required: false,
                parent_container: None,
            };
        }
        
        // If destination is a moon, find its parent planet
        if let Some(dest) = &dest_container {
            if dest.container_type == ContainerType::Moon {
                let containers = self.data_provider.get_object_containers();
                if let Some(dest_parent_planet) = self.find_parent_planet(dest, containers) {
                    log::info!("  Parent: {}", dest_parent_planet.name);
                    
                    // If we're not on the parent planet (or its system), need to go there first
                    if current_container.map_or(true, |c| c.name != dest_parent_planet.name) {
                        // Check if current location is on the parent planet's moon system
                        if let Some(current) = current_container {
                            let is_on_same_planet_system = 
                                current.container_type == ContainerType::Moon &&
                                self.find_parent_planet(current, containers)
                                    .map_or(false, |p| p.name == dest_parent_planet.name);
                            
                            if !is_on_same_planet_system {
                                log::info!("Planetary intercept required: Must approach {} first", dest_parent_planet.name);
                                return PlanetaryInterceptResult {
                                    required: true,
                                    parent_container: Some(dest_parent_planet),
                                };
                            }
                        }
                    }
                    
                    // If we're already on the parent planet or one of its moons, go directly to the destination moon
                    log::info!("Moon intercept required: Direct approach to {}", dest.name);
                    return PlanetaryInterceptResult {
                        required: true,
                        parent_container: Some(Arc::clone(dest)),
                    };
                }
                
                // Fallback if parent not found
                log::info!("Moon intercept required: Direct approach to {}", dest.name);
                return PlanetaryInterceptResult {
                    required: true,
                    parent_container: Some(Arc::clone(dest)),
                };
            }
        }
        
        // If destination is a planet
        if let Some(dest) = &dest_container {
            if dest.container_type == ContainerType::Planet {
                log::info!("Planetary intercept required: Direct approach to {}", dest.name);
                return PlanetaryInterceptResult {
                    required: true,
                    parent_container: Some(Arc::clone(dest)),
                };
            }
        }
        
        // If destination is a POI on a planet/moon
        if let DestinationEntity::Poi(poi) = destination {
            if let Some(poi_container_name) = &poi.obj_container {
                if let Some(current) = current_container {
                    if current.name != *poi_container_name {
                        if let Some(poi_container) = self.data_provider.get_object_container_by_name(poi_container_name) {
                            // If POI is on a different container than current location
                            // For POIs on moons, check if we need to go through parent planet
                            if poi_container.container_type == ContainerType::Moon {
                                let containers = self.data_provider.get_object_containers();
                                if let Some(poi_parent_planet) = self.find_parent_planet(poi_container, containers) {
                                    if poi_parent_planet.name != current.name {
                                        log::info!("  POI Parent: {}", poi_parent_planet.name);
                                        
                                        // Check if we're already on the same planet system
                                        let is_on_same_planet_system = 
                                            current.container_type == ContainerType::Moon &&
                                            self.find_parent_planet(current, containers)
                                                .map_or(false, |p| p.name == poi_parent_planet.name);
                                        
                                        if !is_on_same_planet_system {
                                            log::info!("Planetary intercept required: Must approach {} first for POI", poi_parent_planet.name);
                                            return PlanetaryInterceptResult {
                                                required: true,
                                                parent_container: Some(poi_parent_planet),
                                            };
                                        }
                                    }
                                }
                            }
                            
                            // Need to approach the POI's container
                            log::info!("Container intercept required: Must approach {} for POI", poi_container.name);
                            return PlanetaryInterceptResult {
                                required: true,
                                parent_container: Some(Arc::new(poi_container.clone())),
                            };
                        }
                    }
                }
            }
        }
        
        // Default case - no special handling needed
        PlanetaryInterceptResult {
            required: false,
            parent_container: None,
        }
    }
    
    /// Calculate the optimal intercept point on a planet's surface
    fn calculate_planetary_intercept(
        &self,
        start_pos: &Vector3,
        end_pos: &Vector3,
        planet: &ObjectContainer,
    ) -> Vector3 {
        // Ensure planet has valid coordinates
        if planet.position.x.is_nan() {
            log::error!("Invalid planet coordinates for {}", planet.name);
            // Return a fallback position
            return *start_pos;
        }
        
        // Vector from planet center to start position
        let start_vec = Vector3::new(
            start_pos.x - planet.position.x,
            start_pos.y - planet.position.y,
            start_pos.z - planet.position.z,
        );
        
        // Normalize start vector
        let start_mag = (
            start_vec.x.powi(2) +
            start_vec.y.powi(2) +
            start_vec.z.powi(2)
        ).sqrt();
        
        // Safety check to prevent division by zero
        if start_mag < 0.001 {
            log::warn!("Near-zero magnitude for approach vector to {}", planet.name);
            // Create a fallback intercept vector
            return Vector3::new(
                planet.position.x + planet.om_radius * 0.7071, // sqrt(2)/2
                planet.position.y + planet.om_radius * 0.7071,
                planet.position.z,
            );
        }
        
        // Use standard OM radius or a reasonable multiple of bodyRadius if omRadius isn't available
        let intercept_radius = if planet.om_radius > 0.0 {
            planet.om_radius
        } else {
            planet.body_radius * 1.5
        };
        
        // Vector from planet center to end position
        let end_vec = Vector3::new(
            end_pos.x - planet.position.x,
            end_pos.y - planet.position.y,
            end_pos.z - planet.position.z,
        );
        
        // Normalize end vector
        let end_mag = (
            end_vec.x.powi(2) +
            end_vec.y.powi(2) +
            end_vec.z.powi(2)
        ).sqrt();
        
        // Safety check for end vector
        if end_mag < 0.001 {
            log::warn!("Near-zero magnitude for destination vector to {}", planet.name);
            // Use only start vector for approach
            return Vector3::new(
                planet.position.x + (start_vec.x / start_mag) * intercept_radius,
                planet.position.y + (start_vec.y / start_mag) * intercept_radius,
                planet.position.z + (start_vec.z / start_mag) * intercept_radius,
            );
        }
        
        // Calculate weighted approach vector for optimal interception
        // Weight toward start vector but consider end direction
        let approach_vec = Vector3::new(
            (start_vec.x / start_mag * 0.7) + (end_vec.x / end_mag * 0.3),
            (start_vec.y / start_mag * 0.7) + (end_vec.y / end_mag * 0.3),
            (start_vec.z / start_mag * 0.7) + (end_vec.z / end_mag * 0.3),
        );
        
        // Normalize approach vector
        let approach_mag = (
            approach_vec.x.powi(2) +
            approach_vec.y.powi(2) +
            approach_vec.z.powi(2)
        ).sqrt();
        
        // Final safety check for approach vector
        if approach_mag < 0.001 {
            log::warn!("Calculated zero-magnitude approach vector to {}", planet.name);
            // Generate a fallback vector that's perpendicular to the start-end axis
            // This gives us a valid intercept point even in edge cases
            let fallback_vec = Vector3::new(
                -start_vec.y / start_mag,
                start_vec.x / start_mag,
                start_vec.z / start_mag,
            );
            
            return Vector3::new(
                planet.position.x + fallback_vec.x * intercept_radius,
                planet.position.y + fallback_vec.y * intercept_radius,
                planet.position.z + fallback_vec.z * intercept_radius,
            );
        }
        
        // Calculate optimal intercept using the weighted approach
        let intercept_point = Vector3::new(
            planet.position.x + (approach_vec.x / approach_mag) * intercept_radius,
            planet.position.y + (approach_vec.y / approach_mag) * intercept_radius,
            planet.position.z + (approach_vec.z / approach_mag) * intercept_radius,
        );
        
        log::info!(
            "Calculated intercept for {} at ({:.2}, {:.2}, {:.2})",
            planet.name, intercept_point.x, intercept_point.y, intercept_point.z
        );
        
        intercept_point
    }
    
    /// Creates a navigational route with proper planetary intercepts
    fn create_hierarchical_planetary_route(
        &self,
        start_pos: &Vector3,
        end_pos: &Vector3,
        destination: &DestinationEntity,
    ) -> Option<Vec<Arc<NavNode>>> {
        log::info!("Creating hierarchical planetary route");
        
        // Start with origin node
        let start_node = Arc::new(NavNode::new(
            *start_pos,
            NavNodeType::Origin,
            "Start Position".to_string(),
            None,
        ));
        
        // Find current container
        let current_container = self.core.get_current_object_container();
        
        // Check if there's a direct line of sight
        let los_result = self.check_line_of_sight(start_pos, end_pos);
        if los_result.has_los {
            // Direct path is available
            log::info!("Direct path available - proceeding with simple route");
            let dest_name = match destination {
                DestinationEntity::Poi(poi) => poi.name.clone(),
                DestinationEntity::Container(container) => container.name.clone(),
            };
            
            let end_node = Arc::new(NavNode {
                position: *end_pos,
                parent_node: Some(Arc::clone(&start_node)),
                g_cost: start_pos.distance(end_pos),
                h_cost: 0.0,
                f_cost: start_pos.distance(end_pos),
                node_type: NavNodeType::Destination,
                name: dest_name,
                container_ref: None,
                obstruction_path: false,
                search_direction: SearchDirection::Forward,
            });
            
            return Some(vec![start_node, end_node]);
        }
        
        // Check if planetary intercept is required
        let intercept_result = self.requires_planetary_intercept(
            destination,
            current_container,
        );
        
        // If no intercept required, try bidirectional pathfinding
        if !intercept_result.required || intercept_result.parent_container.is_none() {
            log::info!("No special intercept required, attempting bidirectional pathfinding");
            return self.find_path_bidirectional(start_pos, end_pos);
        }
        
        let primary_intercept = intercept_result.parent_container.unwrap();
        
        // Create an array to build our route
        let mut route_nodes = vec![start_node];
        
        // Calculate primary intercept
        let primary_intercept_point = self.calculate_planetary_intercept(
            start_pos,
            end_pos,
            &primary_intercept,
        );
        
        // Add primary intercept node
        let primary_intercept_node = Arc::new(NavNode {
            position: primary_intercept_point,
            parent_node: Some(Arc::clone(route_nodes.last().unwrap())),
            g_cost: start_pos.distance(&primary_intercept_point),
            h_cost: primary_intercept_point.distance(end_pos),
            f_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(end_pos),
            node_type: NavNodeType::Intermediate,
            name: format!("{} Approach Vector", primary_intercept.name),
            container_ref: Some(Arc::clone(&primary_intercept)),
            obstruction_path: false,
            search_direction: SearchDirection::Forward,
        });
        
        route_nodes.push(Arc::clone(&primary_intercept_node));
        
        // Check if we need a secondary intercept (for moon destinations)
        let dest_container = match destination {
            DestinationEntity::Poi(poi) => {
                poi.obj_container.as_ref().and_then(|name| {
                    self.data_provider.get_object_container_by_name(name)
                }).map(|c| Arc::new(c.clone()))
            },
            DestinationEntity::Container(container) => Some(Arc::clone(container)),
        };
        
        let needs_secondary_intercept = dest_container.as_ref().map_or(false, |dest| {
            dest.container_type == ContainerType::Moon && primary_intercept.name != dest.name
        });
        
        if needs_secondary_intercept && dest_container.is_some() {
            let dest_container = dest_container.unwrap();
            log::info!("Adding secondary intercept through {}", dest_container.name);
            
            // Calculate secondary intercept point
            let secondary_intercept_point = self.calculate_planetary_intercept(
                &primary_intercept_point,
                end_pos,
                &dest_container,
            );
            
            // Add secondary intercept node
            let secondary_intercept_node = Arc::new(NavNode {
                position: secondary_intercept_point,
                parent_node: Some(Arc::clone(&primary_intercept_node)),
                g_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(&secondary_intercept_point),
                h_cost: secondary_intercept_point.distance(end_pos),
                f_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(&secondary_intercept_point) + secondary_intercept_point.distance(end_pos),
                node_type: NavNodeType::Intermediate,
                name: format!("{} Approach Vector", dest_container.name),
                container_ref: Some(Arc::clone(&dest_container)),
                obstruction_path: false,
                search_direction: SearchDirection::Forward,
            });
            
            route_nodes.push(Arc::clone(&secondary_intercept_node));
            
            // Add final destination
            let dest_name = match destination {
                DestinationEntity::Poi(poi) => poi.name.clone(),
                DestinationEntity::Container(_) => "Destination".to_string(),
            };
            
            let end_node = Arc::new(NavNode {
                position: *end_pos,
                parent_node: Some(Arc::clone(&secondary_intercept_node)),
                g_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(&secondary_intercept_point) + secondary_intercept_point.distance(end_pos),
                h_cost: 0.0,
                f_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(&secondary_intercept_point) + secondary_intercept_point.distance(end_pos),
                node_type: NavNodeType::Destination,
                name: dest_name,
                container_ref: None,
                obstruction_path: false,
                search_direction: SearchDirection::Forward,
            });
            
            route_nodes.push(end_node);
        } else {
            // Add final destination directly
            let dest_name = match destination {
                DestinationEntity::Poi(poi) => poi.name.clone(),
                DestinationEntity::Container(_) => "Destination".to_string(),
            };
            
            let end_node = Arc::new(NavNode {
                position: *end_pos,
                parent_node: Some(Arc::clone(&primary_intercept_node)),
                g_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(end_pos),
                h_cost: 0.0,
                f_cost: start_pos.distance(&primary_intercept_point) + primary_intercept_point.distance(end_pos),
                node_type: NavNodeType::Destination,
                name: dest_name,
                container_ref: None,
                obstruction_path: false,
                search_direction: SearchDirection::Forward,
            });
            
            route_nodes.push(end_node);
        }
        
        Some(route_nodes)
    }
    
    /// Get global coordinates for a POI
    fn get_global_coordinates(&self, poi: &PointOfInterest) -> Vector3 {
        // If the POI has a QT marker or no container, it's already in global coords
        if poi.has_qt_marker || poi.obj_container.is_none() {
            return poi.position;
        }
        
        // Find the container
        let container_opt = poi.obj_container.as_ref().and_then(|container_name| {
            self.data_provider.get_object_container_by_name(container_name)
        });
        
        // If container not found, return position as is (as a fallback)
        let container = match container_opt {
            Some(c) => c,
            None => {
                log::error!("Container not found for POI: {}", poi.name);
                return poi.position;
            }
        };
        
        // Transform local coordinates to global
        self.transformer.transform_coordinates(
            &poi.position,
            container,
            TransformDirection::ToGlobal,
        )
    }
    
    /// Plan navigation to a destination by name
    pub fn plan_navigation(&self, destination_name: &str) -> Option<NavigationPlan> {
        let current_position = match self.core.get_current_position() {
            Some(pos) => pos,
            None => {
                log::error!("Navigation origin undefined: position telemetry unavailable");
                return None;
            }
        };
        
        // Try to find the destination as a POI first
        let poi_destination = self.data_provider.get_point_of_interest_by_name(destination_name);
        
        // Then try to find it as a container
        let container_destination = self.data_provider.get_object_container_by_name(destination_name);
        
        // Resolve the destination entity
        let (destination_pos, destination_system, destination_entity) = match (poi_destination, container_destination) {
            (Some(poi), _) => {
                // POI found
                let pos = self.get_global_coordinates(poi);
                let system = poi.system.clone();
                (pos, system, DestinationEntity::Poi(poi.clone()))
            },
            (_, Some(container)) => {
                // Container found
                (container.position, container.system.to_string(), DestinationEntity::Container(Arc::new(container.clone())))
            },
            _ => {
                log::error!("Destination entity '{}' not found in astronomical database", destination_name);
                return None;
            }
        };
        
        // Origin system determination
        let origin_system = self.core.get_current_object_container()
            .map_or_else(|| System::Stanton.to_string(), |c| c.system.to_string());
        
        // Cross-system routing validation
        if destination_system != origin_system {
            log::error!("Interstellar routing prohibited: {} → {}", origin_system, destination_system);
            return None;
        }
        
        log::info!("Planning route to {} in {} system", destination_name, destination_system);
        log::info!(
            "Destination coordinates: ({:.2}, {:.2}, {:.2})",
            destination_pos.x, destination_pos.y, destination_pos.z
        );
        
        // Try to create a hierarchical planetary route
        let path = self.create_hierarchical_planetary_route(
            &current_position,
            &destination_pos,
            &destination_entity,
        );
        
        let path = match path {
            Some(p) => p,
            None => {
                log::error!("Path computation failed: no viable route found");
                return None;
            }
        };
        
        // Navigation plan synthesis
        Some(self.create_navigation_plan(&path))
    }
    
    /// Determine current solar system
    pub fn determine_current_solar_system(&self, plan: Option<&NavigationPlan>) -> System {
        if let Some(p) = plan {
            // Primary directive: Extract system from container metadata
            if let Some(origin_container) = &p.origin_container {
                return origin_container.system;
            }
            
            // Tertiary analysis: Route segment inspection
            if !p.segments.is_empty() {
                // Extract terminal node metadata
                let first_segment = &p.segments[0];
                let last_segment = &p.segments[p.segments.len() - 1];
                
                if let Some(origin_container) = self.data_provider.get_object_container_by_name(&first_segment.from.name) {
                    return origin_container.system;
                }
                
                // Destination analysis fallback
                if let Some(dest_container) = self.data_provider.get_object_container_by_name(&last_segment.to.name) {
                    return dest_container.system;
                }
            }
        } else if let Some(container) = self.core.get_current_object_container() {
            return container.system;
        }
        
        log::warn!("Celestial domain resolution failed: defaulting to Stanton system");
        System::Stanton
    }
    
    /// Format the navigation plan as human-readable instructions
    pub fn format_navigation_instructions(&self, plan: &NavigationPlan) -> String {
        if plan.segments.is_empty() {
            return "No valid navigation plan available.".to_string();
        }
        
        let mut instructions = String::from("NAVIGATION PLAN\n");
        instructions.push_str("===============\n\n");
        
        // Add origin reference if available
        if let Some(origin_container) = &plan.origin_container {
            instructions.push_str(&format!("ORIGIN: {}\n\n", origin_container.name));
        }
        
        if plan.obstruction_detected {
            instructions.push_str("⚠️ OBSTRUCTIONS DETECTED:\n");
            instructions.push_str(&format!(
                "Celestial bodies blocking direct path: {}\n",
                plan.obstructions.join(", ")
            ));
            instructions.push_str(&format!(
                "Multiple jumps required ({} segments, {} quantum jumps)\n\n",
                plan.segments.len(), plan.quantum_jumps
            ));
            
            // Add specific obstruction handling instructions
            instructions.push_str("OBSTRUCTION MITIGATION PLAN:\n");
            
            for obstruction in &plan.obstructions {
                let obstructing_body = self.data_provider.get_object_container_by_name(obstruction);
                
                if let (Some(body), Some(current_pos)) = (obstructing_body, self.core.get_current_position()) {
                    // Find the optimal OM to use for navigation around this body
                    if let Some(last_segment) = plan.segments.last() {
                        let optimal_om = self.find_optimal_orbital_marker(
                            &current_pos,
                            &last_segment.to.position,
                            body,
                        );
                        
                        instructions.push_str(&format!(
                            "- To navigate around {}, route via {}.\n",
                            obstruction, optimal_om.name
                        ));
                        instructions.push_str(&format!(
                            "  Set HUD marker to {} first, then to final destination.\n",
                            optimal_om.name
                        ));
                    }
                }
            }
            
            instructions.push_str("\n");
        } else {
            instructions.push_str("✓ CLEAR PATH AVAILABLE: Direct route possible.\n\n");
        }
        
        instructions.push_str(&format!("Total Distance: {:.2} km\n", plan.total_distance / 1000.0));
        
        // Format time nicely
        let hours = (plan.total_estimated_time / 3600.0) as u32;
        let minutes = ((plan.total_estimated_time % 3600.0) / 60.0) as u32;
        let seconds = (plan.total_estimated_time % 60.0) as u32;
        let mut time_string = String::new();
        
        if hours > 0 {
            time_string.push_str(&format!("{}h ", hours));
        }
        if minutes > 0 || hours > 0 {
            time_string.push_str(&format!("{}m ", minutes));
        }
        time_string.push_str(&format!("{}s", seconds));
        
        instructions.push_str(&format!("Estimated Travel Time: {}\n", time_string));
        instructions.push_str(&format!("Path Complexity: {}\n\n", plan.path_complexity));
        instructions.push_str("ROUTE SEGMENTS:\n");
        
        // Format each segment
        for (index, segment) in plan.segments.iter().enumerate() {
            instructions.push_str(&format!("\n[{}] {} → {}\n", index + 1, segment.from.name, segment.to.name));
            
            // Add obstruction bypass indicator if applicable
            if segment.is_obstruction_bypass {
                instructions.push_str("    ↳ OBSTRUCTION BYPASS SEGMENT\n");
            }
            
            instructions.push_str(&format!("    Distance: {:.2} km\n", segment.distance / 1000.0));
            instructions.push_str(&format!("    Travel Mode: {}\n", segment.travel_type));
            
            // Format time for this segment
            let seg_hours = (segment.estimated_time / 3600.0) as u32;
            let seg_minutes = ((segment.estimated_time % 3600.0) / 60.0) as u32;
            let seg_seconds = (segment.estimated_time % 60.0) as u32;
            let mut seg_time_string = String::new();
            
            if seg_hours > 0 {
                seg_time_string.push_str(&format!("{}h ", seg_hours));
            }
            if seg_minutes > 0 || seg_hours > 0 {
                seg_time_string.push_str(&format!("{}m ", seg_minutes));
            }
            seg_time_string.push_str(&format!("{}s", seg_seconds));
            
            instructions.push_str(&format!("    Time: {}\n", seg_time_string));
            
            // For quantum travel, provide orientation instructions
            if segment.travel_type == TravelType::Quantum {
                instructions.push_str(&format!(
                    "    Align: Pitch {:.1}°, Yaw {:.1}°\n",
                    segment.direction.pitch, segment.direction.yaw
                ));
            }
            
            // Add obstruction information if applicable
            if let Some(obstruction) = &segment.obstruction {
                instructions.push_str(&format!(
                    "    ⚠️ CAUTION: {} may obstruct direct visual on destination\n",
                    obstruction
                ));
            }
        }
        
        instructions
    }
}

/// Type of markers to search for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerSearchType {
    All,
    Orbital,
    QuantumTravel,
}

/// Wrapper for destination entity reference
#[derive(Debug, Clone)]
pub enum DestinationEntity {
    Poi(PointOfInterest),
    Container(Arc<ObjectContainer>),
}

/// Planetary intercept check result
#[derive(Debug, Clone)]
pub struct PlanetaryInterceptResult {
    pub required: bool,
    pub parent_container: Option<Arc<ObjectContainer>>,
}

/// Optimal marker for navigation
#[derive(Debug, Clone)]
pub struct OptimalMarker {
    pub name: String,
    pub position: Vector3,
}