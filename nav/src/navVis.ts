import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { NavigationPlan } from './navPlan';
import { ObjectContainer, System, Vector3 } from './types';

/**
 * Enhanced 3D navigation path visualization with diagnostic capabilities
 */
export class EnhancedNavigationHUD {
    private scene: THREE.Scene;
    private camera: THREE.PerspectiveCamera;
    private renderer: THREE.WebGLRenderer;
    private controls: OrbitControls;

    // Navigation elements
    private navPath: THREE.Line | null = null;
    private waypoints: THREE.Mesh[] = [];
    private celestialBodies: THREE.Mesh[] = [];
    private segmentLabels: THREE.Sprite[] = [];
    private segmentMeshes: THREE.Mesh[] = []; // Store segment meshes for highlighting

    // Scale management and scene centering
    private sceneCenter: THREE.Vector3 = new THREE.Vector3();
    private originOffset: Vector3 | null = null;

    // Animation frame tracking
    private animationFrameId: number | null = null;
    private animationActive: boolean = false;

    // WebGL context monitoring
    private contextLost: boolean = false;
    private lastRenderTime: number = 0;

    // New properties for enhanced functionality
    private currentSystem: string = "Stanton";
    private forceRender: boolean = false;
    private controlsNeedUpdate: boolean = true;
    private lastAnimationTime: number = 0;
    private slowFrameCount: number = 0;
    private qualityLevel: number = 3; // Start with highest quality

    // Animation state for route traversal
    private animatingRoute: boolean = false;
    private currentRouteSegment: number = 0;
    private routeAnimationProgress: number = 0;
    private routeAnimationSpeed: number = 0.001; // Speed multiplier
    private useRouteAnimation: boolean = false;
    private activeHighlightedSegment: number = -1;

    // Colors
    private static readonly QUANTUM_PATH_COLOR = 0x4080ff;
    private static readonly SUBLIGHT_PATH_COLOR = 0x80ff40;
    private static readonly ORIGIN_COLOR = 0x00ff00;
    private static readonly DESTINATION_COLOR = 0xff0000;
    private static readonly WAYPOINT_COLOR = 0xffff00;
    private static readonly OBSTRUCTION_COLOR = 0xff8080;
    private static readonly PLANET_COLOR = 0x808080;
    private static readonly MOON_COLOR = 0xc0c0c0;
    private static readonly HIGHLIGHT_COLOR = 0xffffff;

    // Scaling
    private static readonly SCALE_FACTOR = 1e-6; // Increased from original for better visibility
    private static readonly PLANET_MIN_SIZE = 1.0;
    private static readonly WAYPOINT_SIZE = 0.2;

    /**
     * Initialize the 3D visualization renderer with error handling
     */
    constructor(
        private container: HTMLElement,
        private navigationPlan: NavigationPlan | null,
        private celestialBodiesData: ObjectContainer[]
    ) {
        // Validate container
        if (!container) {
            throw new Error("No valid container element provided for 3D renderer");
        }

        // Check container dimensions
        if (container.clientWidth === 0 || container.clientHeight === 0) {
            console.warn("Container has zero dimensions - setting default size");
            container.style.width = "100%";
            container.style.height = "600px";
        }

        // Initialize Three.js components
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x000015); // Dark space background

        this.camera = new THREE.PerspectiveCamera(
            70, // FOV
            container.clientWidth / container.clientHeight, // Aspect ratio
            0.001, // Reduced near clipping plane for better precision
            100000 // Increased far clipping plane for large-scale scenes
        );
        this.camera.position.z = 15;

        try {
            // Initialize renderer with error handling
            this.renderer = new THREE.WebGLRenderer({
                antialias: true,
                powerPreference: 'high-performance',
                alpha: false // Better performance without alpha
            });

            // Check if WebGL context was successfully acquired
            if (!this.renderer.getContext()) {
                throw new Error("Failed to acquire WebGL context - renderer unavailable");
            }

            this.renderer.setSize(container.clientWidth, container.clientHeight);
            this.renderer.setPixelRatio(window.devicePixelRatio);

            // Optimize renderer
            this.renderer.autoClear = true;
            this.renderer.sortObjects = false; // Disable sorting for performance

            // Add to DOM
            container.appendChild(this.renderer.domElement);

            // Add WebGL context loss handler
            this.renderer.domElement.addEventListener('webglcontextlost', this.handleContextLoss.bind(this), false);
            this.renderer.domElement.addEventListener('webglcontextrestored', this.handleContextRestored.bind(this), false);

        } catch (error) {
            console.error("Error initializing WebGL renderer:", error);

            // Create fallback element to show error
            const fallbackElement = document.createElement('div');
            fallbackElement.style.width = "100%";
            fallbackElement.style.height = "100%";
            fallbackElement.style.backgroundColor = "#000";
            fallbackElement.style.color = "#f00";
            fallbackElement.style.padding = "20px";
            fallbackElement.style.boxSizing = "border-box";
            fallbackElement.style.overflow = "auto";
            fallbackElement.textContent = "WebGL renderer initialization failed. Hardware acceleration may be disabled.";

            container.appendChild(fallbackElement);
            throw error;
        }

        // Add orbit controls for camera manipulation
        this.controls = new OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.05;
        this.controls.screenSpacePanning = true;

        // Add lighting
        this.setupLighting();

        // Add debugging elements
        this.addDebugMarkers();

        // Setup resize handler
        window.addEventListener('resize', this.onWindowResize.bind(this));

        // Add stars background
        this.addStarfield();

        // Render the navigation path if available
        if (navigationPlan) {
            this.renderNavigationPath();
        }

        // Add celestial bodies
        this.renderCelestialBodies();

        // Start animation loop
        this.startAnimationLoop();
    }

    /**
     * Return the current solar system being displayed
     */
    public getCurrentSystem(): string {
        return this.currentSystem;
    }

    /**
     * Handle WebGL context loss
     */
    private handleContextLoss(event: Event): void {
        event.preventDefault();
        console.warn("WebGL context lost - rendering paused");
        this.contextLost = true;

        if (this.animationFrameId !== null) {
            cancelAnimationFrame(this.animationFrameId);
            this.animationFrameId = null;
        }

        // Notify user
        const notification = document.createElement('div');
        notification.style.position = 'absolute';
        notification.style.top = '10px';
        notification.style.left = '10px';
        notification.style.backgroundColor = 'rgba(255,0,0,0.7)';
        notification.style.padding = '10px';
        notification.style.borderRadius = '5px';
        notification.style.color = 'white';
        notification.style.fontWeight = 'bold';
        notification.textContent = 'WebGL context lost - rendering paused';
        notification.id = 'webgl-context-notification';

        this.container.appendChild(notification);
    }

    /**
     * Handle WebGL context restoration
     */
    private handleContextRestored(): void {
        console.log("WebGL context restored - resuming rendering");
        this.contextLost = false;

        // Remove notification if exists
        const notification = document.getElementById('webgl-context-notification');
        if (notification) {
            notification.remove();
        }

        // Restart animation loop
        this.startAnimationLoop();
    }

    /**
     * Start animation loop with error recovery
     */
    private startAnimationLoop(): void {
        if (this.animationActive) return;

        this.animationActive = true;
        this.lastRenderTime = performance.now();
        this.renderScene();
    }

    /**
     * Add a starfield background for context
     */
    private addStarfield(): void {
        const starsGeometry = new THREE.BufferGeometry();
        const starsMaterial = new THREE.PointsMaterial({
            color: 0xFFFFFF,
            size: 0.1,
            sizeAttenuation: false
        });

        const starsVertices = [];
        for (let i = 0; i < 10000; i++) {
            const x = (Math.random() - 0.5) * 2000;
            const y = (Math.random() - 0.5) * 2000;
            const z = (Math.random() - 0.5) * 2000;
            starsVertices.push(x, y, z);
        }

        starsGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starsVertices, 3));
        const stars = new THREE.Points(starsGeometry, starsMaterial);
        this.scene.add(stars);
    }

    /**
     * Add debug visualization elements
     */
    private addDebugMarkers(): void {
        // Add axes helper for orientation
        const axesHelper = new THREE.AxesHelper(5);
        this.scene.add(axesHelper);

        // Add grid helper for scale reference
        const gridHelper = new THREE.GridHelper(10, 10, 0x444444, 0x222222);
        this.scene.add(gridHelper);

        // Add origin marker
        const originGeometry = new THREE.SphereGeometry(0.1, 16, 16);
        const originMaterial = new THREE.MeshBasicMaterial({ color: 0xff0000 });
        const originMarker = new THREE.Mesh(originGeometry, originMaterial);
        this.scene.add(originMarker);

        console.log("Debug markers added to scene");
    }

    /**
     * Set up scene lighting
     */
    private setupLighting(): void {
        // Ambient light for basic visibility
        const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
        this.scene.add(ambientLight);

        // Directional light simulating a star
        const dirLight = new THREE.DirectionalLight(0xffffff, 1);
        dirLight.position.set(50, 50, 50);
        this.scene.add(dirLight);

        // Add a subtle point light at the "sun" position
        const pointLight = new THREE.PointLight(0xffffdd, 2, 100);
        pointLight.position.set(0, 0, 0);
        this.scene.add(pointLight);
    }

    /**
     * Handle window resize events to maintain aspect ratio
     */
    private onWindowResize(): void {
        // Check if container still exists in DOM
        if (!this.container.isConnected) {
            console.warn("Container removed from DOM - canceling resize handler");
            window.removeEventListener('resize', this.onWindowResize.bind(this));
            return;
        }

        this.camera.aspect = this.container.clientWidth / this.container.clientHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    }

    /**
     * Calculate adaptive scale factor based on distance
     */
    private calculateAdaptiveScaleFactor(distance: number): number {
        // Dynamically adjust scale factor based on astronomical distances
        if (distance > 1e12) {
            return EnhancedNavigationHUD.SCALE_FACTOR * 0.1; // Very distant objects
        } else if (distance > 1e10) {
            return EnhancedNavigationHUD.SCALE_FACTOR * 0.5; // Distant objects
        } else if (distance < 1e6) {
            return EnhancedNavigationHUD.SCALE_FACTOR * 2.0; // Very close objects
        }

        return EnhancedNavigationHUD.SCALE_FACTOR;
    }

    /**
     * Convert astronomical coordinates to scene coordinates with improved precision
     */
    private worldToSceneCoords(pos: Vector3): THREE.Vector3 {
        // Initialize origin offset for large coordinates
        if (!this.originOffset && this.navigationPlan && this.navigationPlan.segments && this.navigationPlan.segments.length > 0) {
            const firstSegment = this.navigationPlan.segments[0];
            if (firstSegment && firstSegment.from && firstSegment.from.position) {
                // Use first segment's 'from' position as origin reference
                const origin = firstSegment.from.position;
                this.originOffset = {
                    x: Math.floor(origin.x / 1e8) * 1e8,
                    y: Math.floor(origin.y / 1e8) * 1e8,
                    z: Math.floor(origin.z / 1e8) * 1e8
                };

                console.log(`Scene origin offset set to: (${this.originOffset.x}, ${this.originOffset.y}, ${this.originOffset.z})`);
            }
        }

        // Apply offset if available
        const offsetPos = this.originOffset ? {
            x: pos.x - this.originOffset.x,
            y: pos.y - this.originOffset.y,
            z: pos.z - this.originOffset.z
        } : pos;

        // Calculate distance-based adaptive scale factor
        const distanceFromOrigin = Math.sqrt(
            offsetPos.x * offsetPos.x +
            offsetPos.y * offsetPos.y +
            offsetPos.z * offsetPos.z
        );

        const adaptiveScale = this.calculateAdaptiveScaleFactor(distanceFromOrigin);

        // Normalize very large coordinates using logarithmic scaling for extreme values
        // This prevents floating point precision issues in WebGL
        const maxCoordinate = Math.max(
            Math.abs(offsetPos.x), 
            Math.abs(offsetPos.y), 
            Math.abs(offsetPos.z)
        );
        
        // Apply logarithmic scaling to extreme values
        const logScalingThreshold = 1e9;
        let normalizedScale = adaptiveScale;
        
        if (maxCoordinate > logScalingThreshold) {
            // Apply additional logarithmic scaling for extremely large values
            const logFactor = 1.0 - Math.min(0.9, Math.log10(maxCoordinate) / Math.log10(1e12));
            normalizedScale *= logFactor;
            
            if (maxCoordinate > 1e11) {
                console.log(`Applied logarithmic scaling: ${logFactor.toExponential(2)} to coordinates with magnitude ${maxCoordinate.toExponential(2)}`);
            }
        }

        // Transform to Three.js coordinate system (Y-up)
        return new THREE.Vector3(
            offsetPos.x * normalizedScale,
            offsetPos.z * normalizedScale, // Y-up in Three.js, using z for up
            offsetPos.y * normalizedScale
        );
    }

    /**
     * Render celestial bodies from container data
     */
    private renderCelestialBodies(): void {
        this.celestialBodiesData.forEach(body => {
            // Skip non-physical objects
            if (body.bodyRadius <= 0) return;

            // Calculate scaled radius (with minimum size for visibility)
            const scaledRadius = Math.max(
                body.bodyRadius * EnhancedNavigationHUD.SCALE_FACTOR,
                EnhancedNavigationHUD.PLANET_MIN_SIZE
            );

            try {
                // Create geometry and material
                const geometry = new THREE.SphereGeometry(scaledRadius, 32, 32);
                const material = new THREE.MeshStandardMaterial({
                    color: body.cont_type === 'Planet' ?
                        EnhancedNavigationHUD.PLANET_COLOR :
                        EnhancedNavigationHUD.MOON_COLOR,
                    roughness: 0.7,
                    metalness: 0.3
                });

                // Create mesh and add to scene
                const mesh = new THREE.Mesh(geometry, material);

                // Position the celestial body
                const position = this.worldToSceneCoords({
                    x: body.posX,
                    y: body.posY,
                    z: body.posZ
                });
                mesh.position.copy(position);

                // Add name label
                this.addLabel(position, body.name, 0xffffff);

                // Add to scene and tracking array
                this.scene.add(mesh);
                this.celestialBodies.push(mesh);

                // Add orbital lines for context
                this.addOrbitalIndicator(position, scaledRadius * 1.5);

            } catch (error) {
                console.error(`Error rendering celestial body ${body.name}:`, error);
            }
        });

        console.log(`Rendered ${this.celestialBodies.length} celestial bodies`);
    }

    /**
     * Filter celestial bodies belonging to a specific system
     * Uses name-based identification rather than adding properties
     */
    private filterBodiesBySystem(system: System): ObjectContainer[] {
        return this.celestialBodiesData.filter(body => {
            // Simple name-based system detection
            return body.system === system;
        });
    }

    /**
     * Render a complete solar system
     */
    private renderCompleteSolarSystem(system: System): void {
        console.log(`Rendering complete ${system} solar system`);

        // Store current system
        this.currentSystem = system;

        // Clear existing celestial bodies
        this.clearCelestialBodies();

        // Apply a fixed scale factor to make the solar system viewable
        // Original scale is 1e-6, but we need a much smaller scale for the whole system
        const systemScaleFactor = 1e-10; // Much smaller scale for system view
        
        // Reset origin offset to ensure proper scaling
        this.originOffset = null;

        // Filter bodies for this system by name
        const systemBodies = this.filterBodiesBySystem(system);
        console.log(`Found ${systemBodies.length} bodies in ${system} system`);

        // Find the system star (usually at or near 0,0,0)
        const stars = systemBodies.filter(body => body.cont_type === 'Star');
        console.log(`Found ${stars.length} stars in ${system} system`);
        
        // Determine system center based on star position
        const systemCenter = new THREE.Vector3(0, 0, 0);
        let starPosition = { x: 0, y: 0, z: 0 };
        
        // If we have a star, use its position as the system center
        if (stars.length > 0) {
            starPosition = {
                x: stars[0]!.posX,
                y: stars[0]!.posY,
                z: stars[0]!.posZ
            };
            
            console.log(`Star position: (${starPosition.x}, ${starPosition.y}, ${starPosition.z})`);
        }

        // If no star found, create a default one at origin
        if (stars.length === 0) {
            console.log(`No star found for ${system} system, creating default at origin`);
            this.renderCelestialBodyAtScale(
                { name: `${system} Star`, bodyRadius: 696340000, posX: 0, posY: 0, posZ: 0, cont_type: 'Star' } as ObjectContainer, 
                0xffff80, 
                true, 
                systemScaleFactor
            );
        } else {
            // Render the actual star
            this.renderCelestialBodyAtScale(stars[0], 0xffff80, true, systemScaleFactor);
        }

        // Render planets with custom scale, relative to star position
        const planets = systemBodies.filter(body => body.cont_type === 'Planet');
        planets.forEach(planet => {
            // Adjust position relative to star center
            const adjustedPlanet = { ...planet };
            
            this.renderCelestialBodyAtScale(
                adjustedPlanet, 
                EnhancedNavigationHUD.PLANET_COLOR, 
                true, 
                systemScaleFactor
            );
        });

        // Render moons with custom scale
        const moons = systemBodies.filter(body => body.cont_type === 'Moon');
        moons.forEach(moon => {
            this.renderCelestialBodyAtScale(
                moon, 
                EnhancedNavigationHUD.MOON_COLOR, 
                false, 
                systemScaleFactor
            );

            // Find parent planet based on naming convention
            const parentPlanet = this.findParentPlanet(moon, planets);

            if (parentPlanet) {
                this.renderOrbitalPathAtScale(moon, parentPlanet, systemScaleFactor);
            }
        });

        // Render other objects with custom scale
        const otherBodies = systemBodies.filter(body =>
            body.cont_type !== 'Star' &&
            body.cont_type !== 'Planet' &&
            body.cont_type !== 'Moon'
        );

        otherBodies.forEach(body => {
            if (body.bodyRadius > 0) {
                this.renderCelestialBodyAtScale(
                    body, 
                    0xaaaaaa, 
                    false, 
                    systemScaleFactor
                );
            }
        });

        // Calculate an appropriate view radius based on planetary orbits
        let maxDistance = 0;
        systemBodies.forEach(body => {
            if (body.posX && body.posY && body.posZ && body.cont_type !== 'Star') {
                // Calculate distance from star (not from arbitrary origin)
                const distance = Math.sqrt(
                    Math.pow(body.posX - starPosition.x, 2) + 
                    Math.pow(body.posY - starPosition.y, 2) + 
                    Math.pow(body.posZ - starPosition.z, 2)
                );
                
                // Update max distance if this body is further out
                if (distance > maxDistance) {
                    maxDistance = distance;
                }
            }
        });
        
        // Scale by system view factor and add margin
        const viewRadius = Math.max(maxDistance * systemScaleFactor * 1.2, 50);
        
        console.log(`System bounds: Maximum distance from star: ${maxDistance}`);
        console.log(`Calculated system view radius: ${viewRadius}`);

        // Position camera to view the system from the star's perspective
        const starViewPosition = new THREE.Vector3(
            starPosition.x * systemScaleFactor,
            starPosition.z * systemScaleFactor,  // Y-up in Three.js
            starPosition.y * systemScaleFactor
        );
        
        this.positionCameraForSystemView(
            starViewPosition,
            viewRadius
        );

        console.log(`Rendered ${system} system with ${systemBodies.length} celestial bodies at scale ${systemScaleFactor}`);
    }

    /**
     * Find parent planet for a moon based on naming conventions or proximity
     */
    private findParentPlanet(moon: ObjectContainer, planets: ObjectContainer[]): ObjectContainer | null {
        // First try to find parent by name (often moons are named after planets)
        // e.g., if moon is "Hurston Moon" or "Moon of Hurston", look for "Hurston"
        for (const planet of planets) {
            if (moon.name.includes(planet.name)) {
                return planet;
            }
        }
        
        // If name matching fails, find closest planet
        let closestPlanet: ObjectContainer | null = null;
        let minDistance = Number.MAX_VALUE;
        
        for (const planet of planets) {
            const moonPos = {
                x: moon.posX,
                y: moon.posY,
                z: moon.posZ
            };
            
            const planetPos = {
                x: planet.posX,
                y: planet.posY,
                z: planet.posZ
            };
            
            const distance = this.calcDistance3dFromPositions(moonPos, planetPos);
            
            if (distance < minDistance) {
                minDistance = distance;
                closestPlanet = planet;
            }
        }
        
        return closestPlanet;
    }

    /**
     * Calculate 3D distance between two positions
     */
    private calcDistance3dFromPositions(pos1: Vector3, pos2: Vector3): number {
        return Math.sqrt(
            Math.pow(pos2.x - pos1.x, 2) +
            Math.pow(pos2.y - pos1.y, 2) +
            Math.pow(pos2.z - pos1.z, 2)
        );
    }

    /**
     * Render a celestial body with fixed scale factor (for system view)
     */
    private renderCelestialBodyAtScale(
        body: ObjectContainer,
        color: number,
        isPrimary: boolean,
        scaleFactor: number
    ): void {
        // Find the system star to use as a reference point
        const stars = this.celestialBodiesData.filter(b => b.cont_type === 'Star' && b.system === body.system);
        const starPosition = stars.length > 0 ? 
            { x: stars[0]!.posX, y: stars[0]!.posY, z: stars[0]!.posZ } : 
            { x: 0, y: 0, z: 0 };
            
        // Special handling for stars to prevent them from being too large
        if (body.cont_type === 'Star') {
            // Calculate appropriate star size based on system size
            // Stars are scaled differently than planets to avoid dominating the view
            const starScaleFactor = scaleFactor * 0.1;
            const maxStarSize = 10.0;
            const minStarSize = 2.0;
            
            // Use a smaller scale factor for stars
            const scaledRadius = Math.min(
                Math.max(body.bodyRadius * starScaleFactor, minStarSize),
                maxStarSize
            );
            
            // Create geometry and materials for the star
            const geometry = new THREE.SphereGeometry(scaledRadius, 32, 32);
            const material = new THREE.MeshBasicMaterial({
                color: color,
                transparent: false
            });
            
            // Create and position the star
            const mesh = new THREE.Mesh(geometry, material);
            mesh.position.set(
                body.posX * scaleFactor,
                body.posZ * scaleFactor,  // Y-up in Three.js
                body.posY * scaleFactor
            );
            
            // Add to scene
            this.scene.add(mesh);
            this.celestialBodies.push(mesh);
            
            // Add star glow
            const glowRadius = scaledRadius * 1.5;
            const glowGeometry = new THREE.SphereGeometry(glowRadius, 32, 32);
            const glowMaterial = new THREE.MeshBasicMaterial({
                color: 0xffff99,
                transparent: true,
                opacity: 0.2,
                side: THREE.BackSide
            });
            
            const glowMesh = new THREE.Mesh(glowGeometry, glowMaterial);
            glowMesh.position.copy(mesh.position);
            this.scene.add(glowMesh);
            this.celestialBodies.push(glowMesh);
            
            // Add label
            this.addSimpleLabel(mesh.position, body.name);
            
            return;
        }
        
        // For non-star objects, regular scaling applies
        // Minimum sizes to ensure visibility
        const minSize = isPrimary ? 0.5 : 0.2;
        
        // Calculate radius with minimum size constraint
        const scaledRadius = Math.max(
            body.bodyRadius * scaleFactor,
            minSize
        );
        
        // Create geometry with appropriate detail level
        const detail = isPrimary ? 32 : 16;
        const geometry = new THREE.SphereGeometry(scaledRadius, detail, detail);
        
        // Create material
        const material = new THREE.MeshBasicMaterial({
            color: color,
            transparent: false,
            wireframe: false
        });
        
        // Create mesh and position relative to star
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(
            body.posX * scaleFactor,
            body.posZ * scaleFactor,  // Y-up in Three.js
            body.posY * scaleFactor
        );
        
        // Add to scene
        this.scene.add(mesh);
        this.celestialBodies.push(mesh);
        
        // Add name label (only for primary objects)
        if (isPrimary) {
            this.addSimpleLabel(mesh.position, body.name);
        }
    }

    /**
     * Render an orbital path with fixed scale factor
     */
    private renderOrbitalPathAtScale(
        body: ObjectContainer,
        parentBody: ObjectContainer,
        scaleFactor: number
    ): void {
        // Calculate orbital distance
        const orbitalDistance = this.calcDistance3dFromPositions(
            {x: parentBody.posX, y: parentBody.posY, z: parentBody.posZ},
            {x: body.posX, y: body.posY, z: body.posZ}
        );
        
        // Scale the distance
        const scaledDistance = orbitalDistance * scaleFactor;
        
        // Create orbit geometry
        const orbitGeometry = new THREE.RingGeometry(
            scaledDistance - 0.01,
            scaledDistance + 0.01,
            36
        );
        
        // Create orbit material
        const orbitMaterial = new THREE.MeshBasicMaterial({
            color: 0x4080ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.3,
            depthWrite: false
        });
        
        // Create mesh
        const orbitMesh = new THREE.Mesh(orbitGeometry, orbitMaterial);
        
        // Position at parent
        orbitMesh.position.set(
            parentBody.posX * scaleFactor,
            parentBody.posZ * scaleFactor,  // Y-up in Three.js
            parentBody.posY * scaleFactor
        );
        
        // Calculate normal vector to align orbit plane
        const orbitNormal = new THREE.Vector3(
            body.posX - parentBody.posX,
            body.posY - parentBody.posY,
            body.posZ - parentBody.posZ
        ).normalize();
        
        // Apply rotation to align with orbital plane
        orbitMesh.lookAt(orbitNormal.add(orbitMesh.position));
        orbitMesh.rotateX(Math.PI / 2);
        
        // Add to scene
        this.scene.add(orbitMesh);
        this.celestialBodies.push(orbitMesh);  // Track for cleanup
    }

    /**
     * Add a simple text label for system overview
     */
    private addSimpleLabel(position: THREE.Vector3, text: string): void {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) return;
        
        canvas.width = 256;
        canvas.height = 64;
        
        context.fillStyle = 'rgba(0, 0, 0, 0.7)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.font = 'Bold 20px Arial';
        context.fillStyle = '#ffffff';
        context.textAlign = 'center';
        context.fillText(text, 128, 32);
        
        const texture = new THREE.CanvasTexture(canvas);
        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true
        });
        
        const sprite = new THREE.Sprite(material);
        sprite.position.copy(position);
        sprite.position.y += 1;  // Offset above the object
        sprite.scale.set(5, 1.5, 1);
        
        this.scene.add(sprite);
    }

    /**
     * Add a orbital indicator ring around celestial bodies
     */
    private addOrbitalIndicator(position: THREE.Vector3, radius: number): void {
        const geometry = new THREE.RingGeometry(radius, radius + 0.05, 64);
        const material = new THREE.MeshBasicMaterial({
            color: 0x3080ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.3
        });

        const ring = new THREE.Mesh(geometry, material);
        ring.position.copy(position);
        ring.rotation.x = Math.PI / 2; // Align with XZ plane
        this.scene.add(ring);
    }

    /**
     * Create default star when none is found in the data
     */
    private renderDefaultStar(systemName: string): void {
        // Use a more reasonable star size that won't overwhelm the view
        const starRadius = 696340000; // Sun-like radius in meters
        const maxStarSize = 5.0; // Maximum star size in scene units
        
        // Calculate scaled radius with appropriate constraints
        const scaledRadius = Math.min(
            Math.max(
                starRadius * EnhancedNavigationHUD.SCALE_FACTOR * 0.5, // Reduced scaling factor
                EnhancedNavigationHUD.PLANET_MIN_SIZE * 2
            ),
            maxStarSize // Never exceed this size
        );

        console.log(`Rendering default star with scaled radius: ${scaledRadius}`);

        const geometry = new THREE.SphereGeometry(scaledRadius, 32, 32);
        const material = new THREE.MeshBasicMaterial({ 
            color: 0xffff80,
            transparent: false
        });

        const starMesh = new THREE.Mesh(geometry, material);
        const position = this.worldToSceneCoords({ x: 0, y: 0, z: 0 });

        starMesh.position.copy(position);
        this.scene.add(starMesh);
        this.celestialBodies.push(starMesh);

        // Add light source
        const light = new THREE.PointLight(0xffffee, 1.5, 0);
        light.position.copy(position);
        this.scene.add(light);

        // Add star glow with reduced size
        const glowRadius = scaledRadius * 1.3; // Reduced glow size
        const glowGeometry = new THREE.SphereGeometry(glowRadius, 32, 32);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: 0xffff99,
            transparent: true,
            opacity: 0.15, // Reduced opacity
            side: THREE.BackSide
        });
        
        const glowMesh = new THREE.Mesh(glowGeometry, glowMaterial);
        glowMesh.position.copy(position);
        this.scene.add(glowMesh);
        this.celestialBodies.push(glowMesh);

        // Add label
        this.addLabel(position, `${systemName} Star`, 0xffffaa);
    }

    /**
     * Toggle visibility of the star
     */
    public toggleStarVisibility(): void {
        // Find all star objects in the scene
        const stars = this.celestialBodies.filter(object => {
            // Check if this is a star by checking position or other properties
            // We'll need to use the position since we don't have a direct reference
            const starObjects = this.celestialBodiesData.filter(body => body.cont_type === 'Star');
            
            if (starObjects.length === 0) return false;
            
            const starPos = {
                x: starObjects[0]!.posX * 1e-10, // Use same scale factor as in renderCelestialBodyAtScale
                y: starObjects[0]!.posZ * 1e-10, // Y-up in Three.js
                z: starObjects[0]!.posY * 1e-10
            };
            
            // Check if this object is at the star position with some tolerance
            if (object instanceof THREE.Mesh) {
                const pos = object.position;
                const tolerance = 5; // Allow some difference due to scaling/offsets
                
                const isAtStarPosition = 
                    Math.abs(pos.x - starPos.x) < tolerance &&
                    Math.abs(pos.y - starPos.y) < tolerance &&
                    Math.abs(pos.z - starPos.z) < tolerance;
                    
                return isAtStarPosition;
            }
            
            return false;
        });
        
        // Toggle visibility of all identified star objects
        stars.forEach(star => {
            star.visible = !star.visible;
        });
        
        console.log(`Toggled visibility of ${stars.length} star objects`);
    }

    /**
     * Clear existing celestial bodies
     */
    private clearCelestialBodies(): void {
        this.celestialBodies.forEach(body => {
            this.scene.remove(body);
            if (body instanceof THREE.Mesh) {
                if (body.geometry) body.geometry.dispose();
                if (body.material) {
                    if (Array.isArray(body.material)) {
                        body.material.forEach(m => m.dispose());
                    } else {
                        body.material.dispose();
                    }
                }
            }
        });

        this.celestialBodies = [];
    }

    /**
     * Position camera to view the entire solar system
     */
    private positionCameraForSystemView(center: THREE.Vector3, radius: number): void {
        // Apply a logarithmic scale to handle astronomical distances
        // This prevents the camera from being positioned too far away
        const maxViewDistance = 1000; // Maximum view distance in scene units
        const logScale = Math.log10(radius + 1) / Math.log10(1e12);
        const cameraDistance = Math.min(maxViewDistance, radius * 0.00001 * logScale);

        console.log(`Scaled camera distance: ${cameraDistance} (from radius ${radius})`);

        // Position camera at a reasonable distance
        this.camera.position.set(
            center.x + cameraDistance,
            center.y + cameraDistance / 2,
            center.z + cameraDistance / 2
        );

        // Update camera clipping planes to handle the scene scale
        this.camera.near = 0.001;
        this.camera.far = maxViewDistance * 10;
        this.camera.updateProjectionMatrix();

        this.controls.target.copy(center);
        this.controls.update();
        this.controlsNeedUpdate = true;

        console.log(`Camera positioned at distance ${cameraDistance} from system center`);
    }

    /**
     * Render the navigation path in 3D space with improved visibility
     */
    private renderNavigationPath(): void {
        if (!this.navigationPlan || !this.navigationPlan.segments || this.navigationPlan.segments.length === 0) {
            console.warn("No navigation plan available to render");
            return;
        }

        console.log(`Rendering navigation path with ${this.navigationPlan.segments.length} segments`);

        try {
            // Create path points
            const points: THREE.Vector3[] = [];
            const segments = this.navigationPlan.segments;

            // Add origin point (with null safety)
            if (segments.length > 0 && segments[0] && segments[0].from && segments[0].from.position) {
                const originPos = this.worldToSceneCoords(segments[0].from.position);
                points.push(originPos);

                // Create origin marker (with null safety)
                if (segments[0].from.name) {
                    this.addWaypoint(
                        originPos,
                        segments[0].from.name,
                        EnhancedNavigationHUD.ORIGIN_COLOR,
                        EnhancedNavigationHUD.WAYPOINT_SIZE * 2.5
                    );
                }
            }

            // Process each segment
            segments.forEach((segment, index) => {
                // Add segment point
                const segmentPos = this.worldToSceneCoords(segment.to.position);
                points.push(segmentPos);

                // Add waypoint marker with appropriate color and increased size
                const isDestination = index === segments.length - 1;
                const isObstruction = segment.isObstructionBypass;

                const color = isDestination ? 
                    EnhancedNavigationHUD.DESTINATION_COLOR :
                    isObstruction ? 
                        EnhancedNavigationHUD.OBSTRUCTION_COLOR :
                        EnhancedNavigationHUD.WAYPOINT_COLOR;

                const size = isDestination ?
                    EnhancedNavigationHUD.WAYPOINT_SIZE * 3.0 :
                    EnhancedNavigationHUD.WAYPOINT_SIZE * 2.0;

                this.addWaypoint(segmentPos, segment.to.name, color, size);

                // Create segment label (with null safety)
                if (index < points.length && points[index]) {
                    const prevPoint = points[index]!; // Non-null assertion after bounds check
                    const midpoint = new THREE.Vector3().addVectors(
                        prevPoint,
                        segmentPos
                    ).multiplyScalar(0.5);

                    const distance = (segment.distance / 1000).toFixed(1);
                    const type = segment.travelType === 'quantum' ? 'QT' : 'SL';

                    this.addSegmentLabel(
                        midpoint,
                        `${distance} km (${type})`,
                        segment.travelType === 'quantum' ?
                            EnhancedNavigationHUD.QUANTUM_PATH_COLOR :
                            EnhancedNavigationHUD.SUBLIGHT_PATH_COLOR
                    );
                }
            });

            // Create the path line with thicker line width for visibility
            const pathMaterial = new THREE.LineBasicMaterial({
                vertexColors: true,
                linewidth: 5  // Note: WebGL limit typically caps this at 1.0
            });

            // Create color array for vertex coloring
            const colors: number[] = [];
            segments.forEach((segment, index) => {
                const color = new THREE.Color(
                    segment.travelType === 'quantum' ?
                        EnhancedNavigationHUD.QUANTUM_PATH_COLOR :
                        EnhancedNavigationHUD.SUBLIGHT_PATH_COLOR
                );

                // Each segment needs two colors (from and to)
                if (index === 0) {
                    // First point color
                    colors.push(color.r, color.g, color.b);
                }

                // Second point color
                colors.push(color.r, color.g, color.b);
            });

            // Create geometry with vertex colors
            const pathGeometry = new THREE.BufferGeometry().setFromPoints(points);
            pathGeometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

            // Create line with vertex colors
            this.navPath = new THREE.Line(pathGeometry, pathMaterial);
            this.scene.add(this.navPath);
            
            // Add a thicker line using GL lines for better visibility
            this.addThickPathLines(points, segments);

            // Center camera on the navigation path
            this.centerCameraOnPath(points);

            console.log(`Path rendering complete with ${points.length} points`);

        } catch (error) {
            console.error("Error rendering navigation path:", error);
        }
    }

    /**
     * Add thick path lines using alternate technique
     */
    private addThickPathLines(points: THREE.Vector3[], segments: any[]): void {
        // Create a tube geometry along the path for better visibility
        if (points.length < 2) return;
        
        // Clear previous segment meshes
        this.segmentMeshes.forEach(mesh => {
            this.scene.remove(mesh);
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) {
                if (Array.isArray(mesh.material)) {
                    mesh.material.forEach(m => m.dispose());
                } else {
                    mesh.material.dispose();
                }
            }
        });
        this.segmentMeshes = [];
        
        // Create individual segment tubes for highlighting
        segments.forEach((segment, index) => {
            if (index >= points.length - 1) return;
            
            const color = segment.travelType === 'quantum' ?
                EnhancedNavigationHUD.QUANTUM_PATH_COLOR :
                EnhancedNavigationHUD.SUBLIGHT_PATH_COLOR;
                
            const material = new THREE.MeshBasicMaterial({
                color: color,
                transparent: true,
                opacity: 0.7
            });
            
            // Create a tube for this segment
            const segmentCurve = new THREE.LineCurve3(
                points[index],
                points[index + 1]
            );
            
            const segmentTubeGeometry = new THREE.TubeGeometry(
                segmentCurve,
                10,     // tubular segments
                0.15,   // radius
                8,      // radial segments
                false   // closed
            );
            
            const tubeMesh = new THREE.Mesh(segmentTubeGeometry, material);
            this.scene.add(tubeMesh);
            
            // Store for segment highlighting
            this.segmentMeshes.push(tubeMesh);
            
            // Store original color for highlighting
            tubeMesh.userData.originalColor = color;
            tubeMesh.userData.segmentIndex = index;
        });
    }

    /**
     * Highlight a specific segment of the route
     */
    private highlightSegment(segmentIndex: number): void {
        // Reset all segments to original color
        this.segmentMeshes.forEach(mesh => {
            const material = mesh.material as THREE.MeshBasicMaterial;
            if (material) {
                material.color.set(mesh.userData.originalColor);
                material.opacity = 0.7;
                material.needsUpdate = true;
            }
        });
        
        // Highlight the specified segment
        if (segmentIndex >= 0 && segmentIndex < this.segmentMeshes.length) {
            const highlightMesh = this.segmentMeshes[segmentIndex]!;
            const material = highlightMesh.material as THREE.MeshBasicMaterial;
            
            if (material) {
                material.color.set(EnhancedNavigationHUD.HIGHLIGHT_COLOR);
                material.opacity = 1.0;
                material.needsUpdate = true;
                
                // Create a pulsing effect on the highlighted segment
                this.activeHighlightedSegment = segmentIndex;
            }
        } else {
            this.activeHighlightedSegment = -1;
        }
    }

    /**
     * Update the highlighted segment's animation
     */
    private updateHighlightedSegment(): void {
        if (this.activeHighlightedSegment >= 0 && this.activeHighlightedSegment < this.segmentMeshes.length) {
            const highlightMesh = this.segmentMeshes[this.activeHighlightedSegment]!;
            const material = highlightMesh.material as THREE.MeshBasicMaterial;
            
            if (material) {
                // Create a pulsing opacity effect
                const time = Date.now() * 0.001; // Convert to seconds
                const pulseValue = 0.5 + 0.5 * Math.sin(time * 4); // Oscillate between 0.5 and 1.0
                
                material.opacity = 0.7 + 0.3 * pulseValue;
                material.needsUpdate = true;
            }
        }
    }

    /**
     * Add a waypoint marker with enhanced visibility
     */
    private addWaypoint(
        position: THREE.Vector3,
        name: string,
        color: number,
        size: number
    ): void {
        // Create sphere for waypoint with larger size
        const geometry = new THREE.SphereGeometry(size, 16, 16);
        const material = new THREE.MeshBasicMaterial({ 
            color,
        });
        const waypoint = new THREE.Mesh(geometry, material);
        waypoint.position.copy(position);

        // Add to scene and tracking array
        this.scene.add(waypoint);
        this.waypoints.push(waypoint);

        // Add text label
        this.addEnhancedLabel(position, name, color, size * 2);
        
        // Add a point light at the waypoint for visibility
        const light = new THREE.PointLight(color, 1.0, size * 10);
        light.position.copy(position);
        this.scene.add(light);
        
        // Add a pulse effect
        this.addPulseEffect(position, color, size * 3);
    }

    /**
     * Add an enhanced text label with better visibility
     */
    private addEnhancedLabel(
        position: THREE.Vector3,
        text: string,
        color: number,
        size: number = 2.0
    ): void {
        // Create canvas for label with larger dimensions
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) {
            console.warn(`Unable to get 2D context for label '${text}'`);
            return;
        }

        canvas.width = 512; // Larger canvas for better text quality
        canvas.height = 256;

        // Draw text with improved visibility
        context.fillStyle = 'rgba(0, 0, 0, 0.7)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.strokeStyle = 'rgba(255, 255, 255, 0.8)';
        context.lineWidth = 4;
        context.strokeRect(5, 5, canvas.width - 10, canvas.height - 10);
        
        // Use larger, more visible font
        context.font = 'Bold 32px Arial';
        context.fillStyle = `#${color.toString(16).padStart(6, '0')}`;
        context.textAlign = 'center';
        context.fillText(text, 256, 80);
        
        // Add distance information if available
        const segments = this.navigationPlan?.segments || [];
        const matchingSegment = segments.find(s => 
            s.to && s.to.name === text
        );
        
        if (matchingSegment) {
            const distance = (matchingSegment.distance / 1000).toFixed(1);
            context.font = '24px Arial';
            context.fillText(`${distance} km`, 256, 130);
            
            // Add travel time
            const timeInSeconds = matchingSegment.estimatedTime || 0;
            const minutes = Math.floor(timeInSeconds / 60);
            const seconds = Math.round(timeInSeconds % 60);
            context.fillText(`Time: ${minutes}m ${seconds}s`, 256, 170);
        }

        // Create sprite from canvas with larger scale
        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;

        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true
        });

        const sprite = new THREE.Sprite(material);
        sprite.position.copy(position);
        sprite.position.y += size; // Offset label position
        sprite.scale.set(size * 2, size, 1);

        this.scene.add(sprite);
    }

    /**
     * Add a pulse effect to waypoints for better visibility
     */
    private addPulseEffect(position: THREE.Vector3, color: number, size: number): void {
        // Create a ring geometry
        const geometry = new THREE.RingGeometry(size * 0.8, size, 32);
        const material = new THREE.MeshBasicMaterial({
            color: color,
            transparent: true,
            opacity: 0.7,
            side: THREE.DoubleSide
        });
        
        const ring = new THREE.Mesh(geometry, material);
        ring.position.copy(position);
        
        // Add random rotation for variety
        ring.rotation.x = Math.random() * Math.PI * 2;
        ring.rotation.y = Math.random() * Math.PI * 2;
        
        this.scene.add(ring);
        this.waypoints.push(ring);
        
        // Store animation data for the pulse effect
        // We'll use the userData property to store animation-related data
        ring.userData.pulseAnimation = {
            initialScale: 1.0,
            growing: true,
            rate: 0.01 + Math.random() * 0.02 // Randomize animation rate
        };
    }

    /**
     * Add a segment label for path sections
     */
    private addSegmentLabel(
        position: THREE.Vector3,
        text: string,
        color: number
    ): void {
        // Create canvas for label
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) {
            console.warn(`Unable to get 2D context for segment label '${text}'`);
            return;
        }

        canvas.width = 256;
        canvas.height = 64;

        // Draw background
        context.fillStyle = `rgba(0, 0, 0, 0.5)`;
        context.fillRect(0, 0, canvas.width, canvas.height);

        // Draw text
        context.font = 'Bold 16px Arial';
        context.fillStyle = `#${color.toString(16).padStart(6, '0')}`;
        context.textAlign = 'center';
        context.fillText(text, 128, 32);

        // Create sprite from canvas
        const texture = new THREE.CanvasTexture(canvas);
        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true
        });

        const sprite = new THREE.Sprite(material);
        sprite.position.copy(position);
        sprite.scale.set(1.5, 0.5, 1);

        this.scene.add(sprite);
        this.segmentLabels.push(sprite);
    }

    /**
     * Add a label in legacy format
     */
    private addLabel(
        position: THREE.Vector3,
        text: string,
        color: number
    ): void {
        // Create canvas for label
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) {
            console.warn(`Unable to get 2D context for label '${text}'`);
            return;
        }

        canvas.width = 256;
        canvas.height = 128;

        // Draw text
        context.fillStyle = 'rgba(0, 0, 0, 0.5)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.font = 'Bold 20px Arial';
        context.fillStyle = `#${color.toString(16).padStart(6, '0')}`;
        context.textAlign = 'center';
        context.fillText(text, 128, 64);

        // Create sprite from canvas
        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;

        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true
        });

        const sprite = new THREE.Sprite(material);
        sprite.position.copy(position);
        sprite.position.y += 0.5; // Offset label position
        sprite.scale.set(2, 1, 1);

        this.scene.add(sprite);
    }

    /**
     * Center the camera on the navigation path
     */
    private centerCameraOnPath(points: THREE.Vector3[]): void {
        try {
            // Calculate bounding box
            const box = new THREE.Box3().setFromPoints(points);
            this.sceneCenter = new THREE.Vector3();
            box.getCenter(this.sceneCenter);

            // Calculate appropriate distance
            const size = new THREE.Vector3();
            box.getSize(size);
            const maxDim = Math.max(size.x, size.y, size.z);
            const distance = maxDim * 2;

            // Position camera
            this.camera.position.set(
                this.sceneCenter.x,
                this.sceneCenter.y + distance,
                this.sceneCenter.z
            );
            this.controls.target.copy(this.sceneCenter);
            this.controls.update();

            console.log(`Camera positioned at distance ${distance.toFixed(2)} from center`);
            console.log(`Scene center: (${this.sceneCenter.x.toFixed(2)}, ${this.sceneCenter.y.toFixed(2)}, ${this.sceneCenter.z.toFixed(2)})`);

        } catch (error) {
            console.error("Error centering camera on path:", error);

            // Fallback to default position
            this.camera.position.set(0, 10, 0);
            this.controls.target.set(0, 0, 0);
            this.controls.update();
        }
    }

    /**
     * Update path visualization with new navigation plan
     */
    public updateNavigationPlan(newPlan: NavigationPlan): void {
        console.log("Updating navigation plan visualization...");

        // Remove existing path elements
        if (this.navPath) {
            this.scene.remove(this.navPath);
            this.navPath = null;
        }

        this.waypoints.forEach(waypoint => {
            this.scene.remove(waypoint);
        });
        this.waypoints = [];

        this.segmentLabels.forEach(label => {
            this.scene.remove(label);
        });
        this.segmentLabels = [];

        // Clean up segment meshes
        this.segmentMeshes.forEach(mesh => {
            this.scene.remove(mesh);
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) {
                if (Array.isArray(mesh.material)) {
                    mesh.material.forEach(m => m.dispose());
                } else {
                    mesh.material.dispose();
                }
            }
        });
        this.segmentMeshes = [];

        // Update plan and render
        this.navigationPlan = newPlan;
        this.renderNavigationPath();
    }

    /**
     * Toggle route animation
     */
    public toggleRouteAnimation(): void {
        this.useRouteAnimation = !this.useRouteAnimation;
        this.currentRouteSegment = 0;
        this.routeAnimationProgress = 0;
        
        if (this.useRouteAnimation) {
            console.log("Route animation enabled - camera will follow navigation path");
            
            // Reset camera to start point when beginning animation
            if (this.navigationPlan && this.navigationPlan.segments && this.navigationPlan.segments.length > 0) {
                const startSegment = this.navigationPlan.segments[0];
                if (startSegment && startSegment.from && startSegment.from.position) {
                    const startPos = this.worldToSceneCoords(startSegment.from.position);
                    this.camera.position.set(
                        startPos.x + 5, 
                        startPos.y + 5, 
                        startPos.z + 5
                    );
                    this.controls.target.copy(startPos);
                    this.controls.update();
                }
            }
        } else {
            console.log("Route animation disabled - returning to overview");
            // Return to system overview
            this.centerCameraOnPath(this.getAllPathPoints());
        }
    }
    
    /**
     * Get all path points for camera centering
     */
    private getAllPathPoints(): THREE.Vector3[] {
        const points: THREE.Vector3[] = [];
        
        if (this.navigationPlan && this.navigationPlan.segments) {
            // Add origin point
            if (this.navigationPlan.segments.length > 0 && 
                this.navigationPlan.segments[0]!.from && 
                this.navigationPlan.segments[0]!.from.position) {
                points.push(this.worldToSceneCoords(this.navigationPlan.segments[0]!.from.position));
            }
            
            // Add destination points for each segment
            this.navigationPlan.segments.forEach(segment => {
                if (segment.to && segment.to.position) {
                    points.push(this.worldToSceneCoords(segment.to.position));
                }
            });
        }
        
        return points;
    }
    
    /**
     * Update route animation
     */
    private updateRouteAnimation(deltaTime: number): void {
        if (!this.useRouteAnimation || !this.navigationPlan || !this.navigationPlan.segments) {
            return;
        }
        
        // Get current segment
        const segments = this.navigationPlan.segments;

        if (this.currentRouteSegment >= segments.length) {
            // Animation complete, restart
            this.currentRouteSegment = 0;
            this.routeAnimationProgress = 0;
            return;
        }
        
        const segment = segments[this.currentRouteSegment]!;
        
        // Get start and end points
        const startPos = this.currentRouteSegment === 0 ? 
            this.worldToSceneCoords(segment.from.position) : 
            this.worldToSceneCoords(segments[this.currentRouteSegment - 1]!.to.position);
            
        const endPos = this.worldToSceneCoords(segment.to.position);
        
        // Calculate position along the segment
        this.routeAnimationProgress += this.routeAnimationSpeed * deltaTime;
        
        // Highlight the current segment
        this.highlightSegment(this.currentRouteSegment);
        
        // Move to next segment if complete
        if (this.routeAnimationProgress >= 1.0) {
            this.currentRouteSegment++;
            this.routeAnimationProgress = 0;
            return;
        }
        
        // Calculate current position
        const currentPos = new THREE.Vector3().lerpVectors(
            startPos, 
            endPos, 
            this.routeAnimationProgress
        );
        
        // Position camera near the current position, looking toward the target
        const lookAhead = this.routeAnimationProgress + 0.1 <= 1.0 ? 
            new THREE.Vector3().lerpVectors(startPos, endPos, this.routeAnimationProgress + 0.1) : 
            endPos;
            
        // Calculate camera position slightly offset from the path
        const offset = new THREE.Vector3(2, 1, 2);
        
        // Position camera
        this.camera.position.copy(currentPos).add(offset);
        this.controls.target.copy(lookAhead);
        this.controls.update();
        this.controlsNeedUpdate = true;
    }

    /**
     * Update animations for objects in the scene
     */
    private updateAnimations(): void {
        // Update pulse animations for waypoints
        this.waypoints.forEach(waypoint => {
            // Basic rotation for standard waypoints
            waypoint.rotation.y += 0.01;
            
            // Handle pulse animations
            if (waypoint.userData && waypoint.userData.pulseAnimation) {
                const anim = waypoint.userData.pulseAnimation;
                
                // Determine scale change
                if (anim.growing) {
                    anim.initialScale += anim.rate;
                    if (anim.initialScale > 1.5) {
                        anim.growing = false;
                    }
                } else {
                    anim.initialScale -= anim.rate;
                    if (anim.initialScale < 0.5) {
                        anim.growing = true;
                    }
                }
                
                // Apply scale
                waypoint.scale.set(
                    anim.initialScale,
                    anim.initialScale,
                    anim.initialScale
                );
                
                // Update opacity based on scale
                if (waypoint.material) {
                    const material = waypoint.material as THREE.MeshBasicMaterial;
                    if (material.transparent) {
                        // Fade out as it expands
                        material.opacity = 1.0 - ((anim.initialScale - 0.5) / 1.0);
                    }
                }
            }
        });
        
        // Update highlighted segment animation
        this.updateHighlightedSegment();
    }

    /**
     * Animation loop with performance monitoring
     */
    private renderScene(timestamp?: number): void {
        if (this.contextLost) {
            console.log("Context lost - skipping render");
            return;
        }

        if (!timestamp) timestamp = performance.now();

        try {
            // Throttle frame rate under load
            const frameInterval = 1000 / 30; // Target 30 FPS
            const elapsed = timestamp - this.lastRenderTime;

            if (elapsed < frameInterval && !this.forceRender) {
                // Skip frame to maintain performance
                this.animationFrameId = requestAnimationFrame(this.renderScene.bind(this));
                return;
            }

            // Request next frame first for animation stability
            this.animationFrameId = requestAnimationFrame(this.renderScene.bind(this));
            this.forceRender = false;

            // Calculate delta time for animations
            const deltaTime = timestamp - this.lastRenderTime;
            this.lastRenderTime = timestamp;

            // Profile frame time
            performance.mark('frame-start');

            // Only update controls if there's user interaction
            if (this.controlsNeedUpdate) {
                this.controls.update();
                this.controlsNeedUpdate = false;
            }

            // Update route animation if enabled
            if (this.useRouteAnimation) {
                this.updateRouteAnimation(deltaTime);
            }
            // Otherwise update regular animations periodically
            else if (timestamp - this.lastAnimationTime > 100) { // 10 FPS for animations
                this.updateAnimations();
                this.lastAnimationTime = timestamp;
            }

            // Detect slow frames
            if (deltaTime > 100) { // More than 100ms (less than 10 FPS)
                console.warn(`Slow frame detected: ${deltaTime.toFixed(2)}ms (${(1000 / deltaTime).toFixed(1)} FPS)`);
                this.slowFrameCount++;

                if (this.slowFrameCount > 5) {
                    this.degradeRenderQuality();
                    this.slowFrameCount = 0;
                }
            } else {
                this.slowFrameCount = Math.max(0, this.slowFrameCount - 1);
            }

            // Render scene with optimized settings
            this.renderer.render(this.scene, this.camera);

            // Performance measurement
            performance.mark('frame-end');
            performance.measure('frame-time', 'frame-start', 'frame-end');

        } catch (error) {
            console.error("Critical error in render loop:", error);
            this.handleRenderError(error);
        }
    }

    /**
     * Handle errors in the render loop
     */
    private handleRenderError(error: any): void {
        console.error("Critical render error:", error);

        // Try to recover
        if (this.animationFrameId !== null) {
            cancelAnimationFrame(this.animationFrameId);
            this.animationFrameId = null;
            this.animationActive = false;
        }

        // Attempt to restart after a delay
        setTimeout(() => {
            console.log("Attempting to restart render loop...");
            if (!this.animationActive) {
                this.startAnimationLoop();
            }
        }, 5000);
    }

    /**
     * Degrade render quality to improve performance
     */
    private degradeRenderQuality(): void {
        if (this.qualityLevel <= 0) return;

        console.warn(`Degrading render quality to level ${this.qualityLevel - 1}`);
        this.qualityLevel--;

        switch (this.qualityLevel) {
            case 2:
                // Reduce pixel ratio
                this.renderer.setPixelRatio(
                    Math.min(1.0, window.devicePixelRatio)
                );
                break;

            case 1:
                // Simplify geometries
                this.simplifyGeometries();
                break;

            case 0:
                // Disable non-essential rendering features
                this.renderer.shadowMap.enabled = false;
                this.disableNonEssentialObjects();
                break;
        }
    }

    /**
     * Simplify geometries for better performance
     */
    private simplifyGeometries(): void {
        this.scene.traverse(object => {
            if (object instanceof THREE.Mesh &&
                object.geometry instanceof THREE.SphereGeometry) {

                // Get current parameters
                const params = object.geometry.parameters;

                // Create simplified geometry
                const newGeometry = new THREE.SphereGeometry(
                    params.radius,
                    Math.max(8, Math.floor(params.widthSegments / 2)),
                    Math.max(8, Math.floor(params.heightSegments / 2))
                );

                // Replace geometry
                object.geometry.dispose();
                object.geometry = newGeometry;
            }
        });
    }

    /**
     * Disable non-essential objects for performance
     */
    private disableNonEssentialObjects(): void {
        // Hide orbital indicators and other decorative elements
        this.scene.traverse(object => {
            if (object instanceof THREE.Mesh && object.material) {
                // Keep only essential objects visible
                const material = object.material as THREE.Material;
                if (material.transparent && material.opacity < 0.5) {
                    object.visible = false;
                }
            }
        });
    }

    /**
     * Run diagnostics on the WebGL renderer and scene
     */
    public runDiagnostics(): void {
        console.log("=== Navigation HUD Diagnostics ===");

        // Check WebGL context
        try {
            const gl = this.renderer.getContext();

            // Get renderer info
            const renderInfo = this.renderer.info;
            console.log("Renderer Memory:", renderInfo.memory);
            console.log("Renderer Stats:", renderInfo.render);

            // Try to get GPU info
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                console.log(`GPU Vendor: ${vendor}`);
                console.log(`GPU Renderer: ${renderer}`);
            } else {
                console.log("GPU info not available (WEBGL_debug_renderer_info not supported)");
            }

            // Check for WebGL2
            const isWebGL2 = gl instanceof WebGL2RenderingContext;
            console.log(`WebGL Version: ${isWebGL2 ? '2.0' : '1.0'}`);

            // Check for MSAA support
            const maxSamples = isWebGL2 ? gl.getParameter(gl.MAX_SAMPLES) : 0;
            console.log(`MSAA Support: ${maxSamples > 0 ? `Yes (up to ${maxSamples}x)` : 'No'}`);

            // Check scene content
            console.log(`Scene contains ${this.scene.children.length} objects`);
            console.log(`Waypoints: ${this.waypoints.length}`);
            console.log(`Celestial bodies: ${this.celestialBodies.length}`);

            // Check for rendering issues
            const lostContext = gl.isContextLost();
            console.log(`Context lost: ${lostContext ? 'Yes' : 'No'}`);

            // Verify scene is actually rendering
            console.log(`Animation active: ${this.animationActive ? 'Yes' : 'No'}`);
            console.log(`Last frame time: ${performance.now() - this.lastRenderTime}ms ago`);

            // Check if camera is positioned correctly
            console.log(`Camera position: (${this.camera.position.x.toFixed(2)}, ${this.camera.position.y.toFixed(2)}, ${this.camera.position.z.toFixed(2)})`);
            console.log(`Camera target: (${this.controls.target.x.toFixed(2)}, ${this.controls.target.y.toFixed(2)}, ${this.controls.target.z.toFixed(2)})`);

            // Check current system
            console.log(`Current solar system: ${this.currentSystem}`);

        } catch (error) {
            console.error("Diagnostics failed:", error);
        }

        console.log("=== End Diagnostics ===");
    }

    /**
     * Create a screenshot of the current view
     */
    public takeScreenshot(): string {
        // Force a render to ensure latest state
        this.renderer.render(this.scene, this.camera);

        // Get the data URL of the canvas
        return this.renderer.domElement.toDataURL('image/png');
    }

    /**
     * Clean up resources
     */
    public dispose(): void {
        console.log("Disposing navigation HUD resources...");

        // Stop animation loop
        if (this.animationFrameId !== null) {
            cancelAnimationFrame(this.animationFrameId);
            this.animationFrameId = null;
            this.animationActive = false;
        }

        // Remove event listeners
        window.removeEventListener('resize', this.onWindowResize.bind(this));
        this.renderer.domElement.removeEventListener('webglcontextlost', this.handleContextLoss.bind(this));
        this.renderer.domElement.removeEventListener('webglcontextrestored', this.handleContextRestored.bind(this));

        // Dispose of Three.js resources
        this.scene.traverse((object) => {
            if (object instanceof THREE.Mesh) {
                if (object.geometry) object.geometry.dispose();
                if (object.material) {
                    if (Array.isArray(object.material)) {
                        object.material.forEach(material => this.disposeMaterial(material));
                    } else {
                        this.disposeMaterial(object.material);
                    }
                }
            } else if (object instanceof THREE.LineSegments || object instanceof THREE.Line) {
                if (object.geometry) object.geometry.dispose();
                if (object.material) {
                    if (Array.isArray(object.material)) {
                        object.material.forEach(material => this.disposeMaterial(material));
                    } else {
                        this.disposeMaterial(object.material);
                    }
                }
            }
        });

        // Dispose of controls
        this.controls.dispose();

        // Dispose of renderer
        this.renderer.dispose();

        // Remove renderer from DOM
        if (this.renderer.domElement.parentNode) {
            this.renderer.domElement.parentNode.removeChild(this.renderer.domElement);
        }

        console.log("Navigation HUD resources successfully disposed");
    }

    /**
     * Helper to properly dispose of Three.js materials
     */
    private disposeMaterial(material: THREE.Material): void {
        // Dispose of any textures
        if (material instanceof THREE.MeshBasicMaterial) {
            if (material.map) material.map.dispose();
            if (material.lightMap) material.lightMap.dispose();
            if (material.aoMap) material.aoMap.dispose();
            if (material.alphaMap) material.alphaMap.dispose();
            if (material.envMap) material.envMap.dispose();
        }
        else if (material instanceof THREE.MeshStandardMaterial) {
            if (material.map) material.map.dispose();
            if (material.lightMap) material.lightMap.dispose();
            if (material.aoMap) material.aoMap.dispose();
            if (material.emissiveMap) material.emissiveMap.dispose();
            if (material.bumpMap) material.bumpMap.dispose();
            if (material.normalMap) material.normalMap.dispose();
            if (material.displacementMap) material.displacementMap.dispose();
            if (material.roughnessMap) material.roughnessMap.dispose();
            if (material.metalnessMap) material.metalnessMap.dispose();
            if (material.alphaMap) material.alphaMap.dispose();
            if (material.envMap) material.envMap.dispose();
        }
        else if (material instanceof THREE.SpriteMaterial) {
            if (material.map) material.map.dispose();
        }

        // Dispose of the material itself
        material.dispose();
    }
}