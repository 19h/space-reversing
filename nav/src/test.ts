import { SCNavigationPlanner } from "./navPlan";
import { CoordinateTransformer } from "./navPlanUtils";
import { pointsOfInterest } from "./objPoi";
import { objectContainers } from "./objContainers";

/**
 * Test navigation planning functionality
 */
function testNavigationPlanner(): void {
    console.log("=== Navigation Planner Test ===");
    
    try {
        // Initialize the navigation planner
        console.log("Initializing navigation planner...");
        const planner = new SCNavigationPlanner(pointsOfInterest, objectContainers);
        
        planner.setPositionLocal("Hurston", -328.9052, -785.9761, 564.1687);
        console.log(`Setting current position: Hurston (-328.9052, -785.9761, 564.1687)`);
        
        // Set destination
        const destinationName = "Shubin Mining Facility SCD-1";
        console.log(`Planning navigation to: ${destinationName}`);
        
        // Plan navigation
        const plan = planner.planNavigation(destinationName);
        
        if (!plan) {
            console.error("No viable path found to destination");
            return;
        }
        
        // Display navigation plan details
        console.log("\n=== Navigation Plan ===");
        console.log(`Total distance: ${(plan.totalDistance / 1000).toFixed(2)} km`);
        console.log(`Estimated travel time: ${(plan.totalEstimatedTime / 60).toFixed(2)} minutes`);
        console.log(`Quantum jumps required: ${plan.quantumJumps}`);
        console.log(`Path complexity: ${plan.pathComplexity}`);
        console.log(`Origin container: ${plan.originContainer?.name || 'None'}`);
        
        if (plan.obstructionDetected) {
            console.log(`Obstructions detected: ${plan.obstructions.join(', ')}`);
        }
        
        // Display waypoints
        console.log("\n=== Waypoints ===");
        plan.segments.forEach((segment, index) => {
            console.log(`[${index + 1}] ${segment.from.name} (${segment.from.type}) → ${segment.to.name} (${segment.to.type})`);
            console.log(`    From position: (${segment.from.position.x.toFixed(2)}, ${segment.from.position.y.toFixed(2)}, ${segment.from.position.z.toFixed(2)})`);
            console.log(`    To position: (${segment.to.position.x.toFixed(2)}, ${segment.to.position.y.toFixed(2)}, ${segment.to.position.z.toFixed(2)})`);
            console.log(`    Distance: ${(segment.distance / 1000).toFixed(2)} km`);
            console.log(`    Travel type: ${segment.travelType}`);
            console.log(`    Estimated time: ${(segment.estimatedTime / 60).toFixed(2)} minutes`);
            console.log(`    Direction: Pitch ${segment.direction.pitch.toFixed(2)}°, Yaw ${segment.direction.yaw.toFixed(2)}°`);
            
            if (segment.obstruction) {
                console.log(`    Note: Path obstructed by ${segment.obstruction}`);
                if (segment.isObstructionBypass) {
                    console.log(`    This segment is part of an obstruction bypass route`);
                }
            }
        });
        
        // Find nearby POIs for context
        const nearbyPOIs = planner.findNearbyPOIs(3);
        console.log("\n=== Nearby Points of Interest ===");
        nearbyPOIs.forEach((poi, index) => {
            console.log(`[${index + 1}] ${poi.name} - ${poi.distance.toFixed(2)} km away`);
        });
        
        // Clean up resources
        console.log("\nTest completed successfully");
        
        CoordinateTransformer.clearCache();
    } catch (error) {
        console.error("Error during navigation test:", error);
    }
}

// Run the test
testNavigationPlanner();
