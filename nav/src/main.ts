// Import required modules
import { SCNavigationPlanner } from "./navPlan";
import { pointsOfInterest } from "./objPoi";
import { objectContainers } from "./objContainers";
import { EnhancedNavigationHUD } from "./navVis";
import { CoordinateTransformer } from "./navPlanUtils";

// Wait for DOM content to be loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log("DOM loaded - initializing navigation application");
    
    // Check if app already exists in window context
    if (!(window as any).navApp) {
        try {
            initNavApp();
        } catch (error) {
            console.error("Failed to initialize navigation application:", error);
            showErrorMessage(`Navigation system initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    } else {
        console.log("Navigation application already initialized");
    }
});

/**
 * Initialize the navigation application
 */
function initNavApp(): void {
    console.log("Starting Star Citizen Navigation Application...");
    
    // Create navigation application
    const navApp = new StarCitizenNavigationApp();
    
    // Set position using local coordinates relative to Hurston
    navApp.setPosition("Hurston", -328.9052, -785.9761, 564.1687);
    
    // Plan navigation to a destination
    navApp.navigate("Bennyhenge");
    
    // Add window callback to prevent duplicate initialization
    (window as any).navApp = navApp;
    
    // Add event handlers for browser window events
    window.addEventListener("beforeunload", () => {
        if ((window as any).navApp) {
            (window as any).navApp.dispose();
        }
    });
    
    console.log("Navigation application ready");
}

/**
 * Display an error message to the user
 */
function showErrorMessage(message: string): void {
    const errorElement = document.createElement("div");
    errorElement.style.color = "red";
    errorElement.style.padding = "20px";
    errorElement.style.backgroundColor = "#000";
    errorElement.style.border = "1px solid red";
    errorElement.style.margin = "20px";
    errorElement.style.borderRadius = "5px";
    errorElement.style.fontFamily = "monospace";
    errorElement.textContent = message;
    
    document.body.appendChild(errorElement);
}

/**
 * Main navigation application with error handling and diagnostics
 */
class StarCitizenNavigationApp {
    private planner!: SCNavigationPlanner;
    private renderer: EnhancedNavigationHUD | null = null;
    private initialized: boolean = false;
    private canvasElement: HTMLElement | null = null;
    
    /**
     * Initialize the navigation system with error handling
     */
    constructor() {
        console.log("Initializing Star Citizen Navigation System...");
        
        try {
            // Initialize the navigation planner
            this.planner = new SCNavigationPlanner(pointsOfInterest, objectContainers);
            console.log(`Initialized navigation planner with ${pointsOfInterest.length} POIs and ${objectContainers.length} containers`);
            
            // Find or create canvas container
            this.initializeCanvas();
            
            this.initialized = true;
            console.log("Navigation system initialization complete");
            
        } catch (error) {
            console.error("Fatal error during navigation system initialization:", error);
            this.showErrorMessage("Failed to initialize navigation system. See console for details.");
        }
    }
    
    /**
     * Initialize the canvas element for rendering
     */
    private initializeCanvas(): void {
        // Try to find existing canvas
        this.canvasElement = document.getElementById("canvas");
        
        // Create canvas if it doesn't exist
        if (!this.canvasElement) {
            console.log("Canvas element not found - creating one");
            
            this.canvasElement = document.createElement("div");
            this.canvasElement.id = "canvas";
            this.canvasElement.style.width = "100%";
            this.canvasElement.style.height = "600px";
            this.canvasElement.style.backgroundColor = "#000";
            this.canvasElement.style.position = "relative";
            this.canvasElement.style.overflow = "hidden";
            this.canvasElement.style.borderRadius = "4px";
            
            // Add to document
            document.body.appendChild(this.canvasElement);
        }
        
        // Ensure canvas has dimensions
        if (this.canvasElement.clientWidth === 0 || this.canvasElement.clientHeight === 0) {
            console.warn("Canvas has zero dimensions - setting default size");
            this.canvasElement.style.width = "100%";
            this.canvasElement.style.height = "600px";
        }
    }
    
    /**
     * Display an error message to the user
     */
    private showErrorMessage(message: string): void {
        if (!this.canvasElement) {
            this.initializeCanvas();
        }
        
        if (this.canvasElement) {
            const errorElement = document.createElement("div");
            errorElement.style.position = "absolute";
            errorElement.style.top = "50%";
            errorElement.style.left = "50%";
            errorElement.style.transform = "translate(-50%, -50%)";
            errorElement.style.backgroundColor = "rgba(255, 0, 0, 0.8)";
            errorElement.style.color = "white";
            errorElement.style.padding = "20px";
            errorElement.style.borderRadius = "5px";
            errorElement.style.textAlign = "center";
            errorElement.style.fontFamily = "Arial, sans-serif";
            errorElement.style.fontSize = "16px";
            errorElement.style.maxWidth = "80%";
            errorElement.textContent = message;
            
            this.canvasElement.appendChild(errorElement);
        } else {
            // Fallback to alert if no canvas element
            alert(message);
        }
    }
    
    /**
     * Set current position using local coordinates (relative to container)
     */
    public setPosition(containerName: string, localX: number, localY: number, localZ: number): void {
        if (!this.initialized) {
            console.error("Cannot set position - navigation system not initialized");
            return;
        }
        
        try {
            this.planner.setPositionLocal(containerName, localX, localY, localZ);
        } catch (error) {
            console.error("Error setting position:", error);
            this.showErrorMessage(`Failed to set position: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    /**
     * Perform navigation planning and visualization
     */
    public navigate(destinationName: string): void {
        if (!this.initialized) {
            console.error("Cannot navigate - navigation system not initialized");
            return;
        }
        
        try {
            console.log(`Planning navigation to ${destinationName}...`);
            
            // Plan navigation route
            const plan = this.planner.planNavigation(destinationName);
            
            if (!plan) {
                this.showErrorMessage(`No viable path found to ${destinationName}`);
                return;
            }
            
            // Get and display instruction text
            const instructions = this.planner.formatNavigationInstructions(plan);
            console.log(instructions);
            
            // Display instructions in DOM
            this.displayInstructions(instructions);
            
            // Determine which solar system this route is in
            const currentSystem = this.planner.determineCurrentSolarSystem(plan);
            console.log(`Route is in the ${currentSystem} system`);
            
            // Initialize or update 3D visualization
            if (!this.renderer) {
                // Create new renderer if none exists
                if (this.canvasElement) {
                    console.log(`Initializing 3D navigation visualization for ${currentSystem} system`);
                    this.renderer = new EnhancedNavigationHUD(
                        this.canvasElement,
                        plan,
                        objectContainers
                    );
                    
                    // Render the complete solar system
                    this.renderer.renderCompleteSolarSystem(currentSystem);
                    
                    // Run diagnostics
                    this.renderer.runDiagnostics();
                }
            } else {
                // Update existing renderer
                this.renderer.updateNavigationPlan(plan);
                
                // Re-render the solar system if needed
                if (this.renderer.getCurrentSystem() !== currentSystem) {
                    this.renderer.renderCompleteSolarSystem(currentSystem);
                }
            }
            
        } catch (error) {
            console.error("Error during navigation:", error);
            this.showErrorMessage(`Navigation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    /**
     * Display navigation instructions in the DOM
     */
    private displayInstructions(instructions: string): void {
        // Find or create instructions container
        let instructionsElement = document.getElementById("navigation-instructions");
        
        if (!instructionsElement) {
            instructionsElement = document.createElement("pre");
            instructionsElement.id = "navigation-instructions";
            instructionsElement.style.fontFamily = "monospace";
            instructionsElement.style.padding = "10px";
            instructionsElement.style.backgroundColor = "#111";
            instructionsElement.style.color = "#0f0";
            instructionsElement.style.borderRadius = "4px";
            instructionsElement.style.overflow = "auto";
            instructionsElement.style.maxHeight = "400px";
            instructionsElement.style.marginTop = "20px";
            
            // Add to document
            if (this.canvasElement && this.canvasElement.parentNode) {
                this.canvasElement.parentNode.insertBefore(instructionsElement, this.canvasElement.nextSibling);
            } else {
                document.body.appendChild(instructionsElement);
            }
        }
        
        // Set instruction text
        instructionsElement.textContent = instructions;
    }
    
    /**
     * Take screenshot of the current navigation view
     */
    public takeScreenshot(): string | null {
        if (!this.renderer) {
            console.warn("Cannot take screenshot - renderer not initialized");
            return null;
        }
        
        return this.renderer.takeScreenshot();
    }
    
    /**
     * Clean up resources
     */
    public dispose(): void {
        console.log("Disposing navigation application resources...");
        
        if (this.renderer) {
            this.renderer.dispose();
            this.renderer = null;
        }
        
        // Clear coordinate transformer cache
        CoordinateTransformer.clearCache();
        
        this.initialized = false;
    }
}