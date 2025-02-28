```
          /\,%,_
          \%%%/,\       In silence drift, through void unknown,
        _.-"%%|//%      A mapless path your screen has shown.
      .'  .-"  /%%%
  _.-'_.-" 0)   \%%%    Coordinates fade, the stars align,
 /.\.'           \%%%   To whispers lost beyond defined.
 \ /      _,      %%%
  `"---"~`\   _,*'\%%'   _,--""""-,%%,
           )*^     `""~~`         \%%%,
         _/                         \%%%
     _.-`/       uncharted           |%%,___
 _.-"   /    worlds await your       |%%   .`\
/\     /    gaze, their secrets      \%'   \ /
\ \ _,/     shine in stellar haze.    \`""~~`
 `"` /-.,_/                            \
     \___,'                       \.-"`/      
                                   `--'
           Navigate shadows, chart the spark,
             Secrets found in deepest dark.
```

# Space Navigation System

A comprehensive 3D celestial navigation system with advanced pathfinding, coordinate transformations, and collision detection for space simulation environments.

## Overview

Space Navigation System is a high-performance Rust library designed for accurate interplanetary navigation calculations with realistic physics considerations. It implements optimized bidirectional A* search with pre-computed visibility graphs, quaternion-based coordinate transformations, and sophisticated collision detection algorithms.

## Features

- **Advanced Pathfinding**: Bidirectional A* search algorithm with optimized performance for interplanetary routes
- **Obstacle Avoidance**: Automatically detects celestial bodies in the path and calculates optimal detour routes
- **Quaternion-based Rotations**: Precise coordinate transformations between global and local reference frames
- **Planetary Rotation**: Accounts for planetary rotation when calculating surface coordinates
- **Path Complexity Analysis**: Categorizes routes based on complexity and provides detailed navigation instructions
- **Efficient Caching**: Implements smart caching for expensive coordinate transformations
- **JSON Data Loading**: Loads celestial object data and points of interest from structured JSON files
- **Travel Time Estimation**: Calculates realistic travel times with acceleration and deceleration profiles
- **Quantum Travel Support**: Special handling for both subluminal and quantum (FTL) travel mechanics

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
space-navigation-system = "0.1.0"
```

## Quick Start

```rust
use space_navigation_system::{SpaceNavigationSystem, types::StaticAstronomicalData};

fn main() {
    // Load navigation data (containers and points of interest)
    let data = StaticAstronomicalData::new(pois, containers);
    
    // Create navigation system
    let mut nav_system = SpaceNavigationSystem::new(data);
    
    // Set current position (can be in local or global coordinates)
    nav_system.set_position_local("Hurston", -328.91, -785.98, 564.17);
    
    // Plan navigation to a destination
    let plan = nav_system.plan_navigation("Shubin Mining Facility SCD-1");
    
    if let Some(plan) = plan {
        // Get human-readable navigation instructions
        let instructions = nav_system.format_navigation_instructions(&plan);
        println!("{}", instructions);
    }
}
```

## Architecture

The navigation system is built with a modular architecture:

```
┌─────────────────────────────────────┐
│       SpaceNavigationSystem         │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│         NavigationPlanner           │
└───────────────┬─────────────────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
┌───────────────┐ ┌─────────────────────┐
│ NavigationCore│ │CoordinateTransformer│
└───────────────┘ └─────────────────────┘
        ▲               ▲
        └───────┬───────┘
                │
                ▼
┌─────────────────────────────────────┐
│    AstronomicalDataProvider         │
└─────────────────────────────────────┘
```

## Core Components

### CoordinateTransformer

Specialized utility for transforming coordinates between global and local reference frames with caching for expensive calculations.

```rust
let transformer = CoordinateTransformer::new();
let global_coords = transformer.transform_coordinates(
    &local_coords,
    &container,
    TransformDirection::ToGlobal
);
```

### NavigationCore

Provides core navigation functionality including position tracking, vector calculations, and closest point determination.

```rust
let nav_core = NavigationCore::new(data_provider);
nav_core.set_position(x, y, z);
let nav_data = nav_core.get_navigation_data();
```

### NavigationPlanner

Advanced pathfinding system with bidirectional A* search and pre-computed visibility graphs for efficient route calculation.

```rust
let planner = NavigationPlanner::new(data_provider);
let plan = planner.plan_route("Lorville", "Shubin Mining Facility SCD-1");
```

### Data Loading

Load celestial objects and points of interest from JSON files.

```rust
let containers = load_containers("data/containers.json")?;
let pois = load_pois("data/pois.json")?;
```

## Navigation Plan Example

When executing a navigation plan, the system provides detailed instructions:

```
NAVIGATION PLAN
===============

ORIGIN: Hurston

SUMMARY:
Distance: 43,854,328 km
Estimated Travel Time: 14m 22s
Path Complexity: MultiJump

ROUTE SEGMENTS:

[1] Lorville → Hurston OM-1
    Distance: 1,500.00 km
    Travel Mode: Sublight
    Time: 5m 10s

[2] Hurston OM-1 → Daymar OM-6
    Distance: 19,204,875.23 km
    Travel Mode: Quantum
    Time: 5m 32s
    Align: Pitch -1.4°, Yaw 223.7°

[3] Daymar OM-6 → Shubin Mining Facility SCD-1
    Distance: 305.88 km
    Travel Mode: Sublight
    Time: 3m 40s
```

## Data Models

The system uses several specialized data structures:

- **ObjectContainer**: Represents celestial bodies (planets, moons, space stations)
- **PointOfInterest**: Locations on or near celestial bodies
- **Vector3**: 3D vector representation
- **Quaternion**: For precise rotational calculations
- **NavigationPlan**: Complete route with multiple segments
- **PathSegment**: Individual segments in a navigation route

## Performance Considerations

The system implements several performance optimizations:

1. **Caching**: Coordinate transformations are cached with automatic pruning
2. **Pre-computed Visibility**: Navigation nodes use pre-computed visibility graphs
3. **Optimized Pathfinding**: Bidirectional A* search algorithm reduces search space
4. **Lazy Initialization**: Navigation markers are created on-demand

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

* The quaternion implementation is inspired by modern aerospace navigation systems
* Pathfinding algorithms derived from advanced graph theory research
* Special thanks to all contributors and testers

---

*Note: This navigation system is designed for simulation environments and should not be used for real-world space navigation.*
