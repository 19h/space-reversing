import { SCNavigationPlanner } from "./navPlan";
import { pointsOfInterest } from "./objPoi";
import { objectContainers } from "./objContainers";

function navigateWithPathPlanning() {
    // Create navigation instance
    const planner =
        new SCNavigationPlanner(
            pointsOfInterest,
            objectContainers,
        );

    // Update current position (these would come from game data)
    // This places us on Daymar
    planner.updatePosition(18929997543, 2610188977, -85124);

    // Plan navigation to a destination
    const plan = planner.planNavigation("Microtech");

    if (plan) {
        // Output the navigation instructions
        const instructions = planner.formatNavigationInstructions(plan);
        console.log(instructions);
    } else {
        console.error("Failed to create navigation plan");
    }
}

navigateWithPathPlanning();