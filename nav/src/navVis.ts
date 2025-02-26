import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { NavigationPlan } from './navPlan';
import { ObjectContainer, Vector3 } from './types';

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
    
    // Scale management and scene centering
    private sceneCenter: THREE.Vector3 = new THREE.Vector3();
    private originOffset: Vector3 | null = null;
    
    // Animation frame tracking
    private animationFrameId: number | null = null;
    private animationActive: boolean = false;
    
    // WebGL context monitoring
    private contextLost: boolean = false;
    private lastRenderTime: number = 0;
    
    // Colors
    private static readonly QUANTUM_PATH_COLOR = 0x4080ff;
    private static readonly SUBLIGHT_PATH_COLOR = 0x80ff40;
    private static readonly ORIGIN_COLOR = 0x00ff00;
    private static readonly DESTINATION_COLOR = 0xff0000;
    private static readonly WAYPOINT_COLOR = 0xffff00;
    private static readonly OBSTRUCTION_COLOR = 0xff8080;
    private static readonly PLANET_COLOR = 0x808080;
    private static readonly MOON_COLOR = 0xc0c0c0;
    
    // Scaling
    private static readonly SCALE_FACTOR = 1e-6; // Increased for better visibility
    private static readonly PLANET_MIN_SIZE = 1.0;
    private static readonly STAR_SCALE_MULTIPLIER = 3.0;
    
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

    private calculateAdaptiveScaleFactor(distance: number): number {
        // Dynamically adjust scale factor based on astronomical distances
        // Prevents objects from being too small or too large
        if (distance > 1e12) {
            return this.SCALE_FACTOR * 0.1; // Very distant objects
        } else if (distance > 1e10) {
            return this.SCALE_FACTOR * 0.5; // Distant objects
        } else if (distance < 1e6) {
            return this.SCALE_FACTOR * 2.0; // Very close objects
        }
        
        return this.SCALE_FACTOR;
    }
    
    /**
     * Convert astronomical coordinates to scene coordinates with improved precision
     */
    private worldToSceneCoords(pos: Vector3): THREE.Vector3 {
        // Initialize origin offset for large coordinates
        if (!this.originOffset && this.navigationPlan?.segments?.length > 0) {
            // Use first segment's 'from' position as origin reference
            const origin = this.navigationPlan.segments[0].from.position;
            this.originOffset = {
                x: Math.floor(origin.x / 1e8) * 1e8,
                y: Math.floor(origin.y / 1e8) * 1e8,
                z: Math.floor(origin.z / 1e8) * 1e8
            };
            
            console.log(`Scene origin offset set to: (${this.originOffset.x}, ${this.originOffset.y}, ${this.originOffset.z})`);
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
        
        // Transform to Three.js coordinate system (Y-up)
        return new THREE.Vector3(
            offsetPos.x * adaptiveScale,
            offsetPos.z * adaptiveScale, // Y-up in Three.js, using z for up
            offsetPos.y * adaptiveScale
        );
    }
    
    /**
     * Render celestial bodies from container data
     */
    private renderCelestialBodies(): void {
        // Clear existing celestial bodies
        this.celestialBodies.forEach(body => this.scene.remove(body));
        this.celestialBodies = [];
        
        // Infer solar system from navigation plan or current position
        const currentSystem = this.determineCurrentSystem();
        console.log(`Rendering celestial bodies for ${currentSystem} system`);
        
        // Star rendering (system primary)
        const systemStar = this.celestialBodiesData.find(body => 
            body.cont_type === 'Star' && 
            (body.solarSystem === currentSystem || 
             body.name.includes(currentSystem))
        );
        
        if (systemStar) {
            this.renderStar(systemStar);
        }
        
        // Filter for current system bodies and sort by type for layered rendering
        const systemBodies = this.celestialBodiesData.filter(body => 
            (body.solarSystem === currentSystem || 
             body.name.includes(currentSystem) || 
             (currentSystem === "Stanton" && !body.solarSystem)) && 
            body.cont_type !== 'Star'
        );
        
        // Render planets first (primary bodies)
        const planets = systemBodies.filter(body => body.cont_type === 'Planet');
        planets.forEach(planet => {
            this.renderCelestialBody(planet, EnhancedNavigationHUD.PLANET_COLOR, true);
            
            // Calculate and render orbital paths
            this.renderOrbitalPath(planet, systemStar);
        });
        
        // Render moons (secondary bodies)
        const moons = systemBodies.filter(body => body.cont_type === 'Moon');
        moons.forEach(moon => {
            this.renderCelestialBody(moon, EnhancedNavigationHUD.MOON_COLOR, false);
            
            // Find parent planet and render moon orbit
            const parentPlanet = planets.find(p => moon.parentBody === p.name);
            if (parentPlanet) {
                this.renderOrbitalPath(moon, parentPlanet);
            }
        });
        
        // Render other celestial objects
        const otherBodies = systemBodies.filter(body => 
            body.cont_type !== 'Planet' && 
            body.cont_type !== 'Moon'
        );
        
        otherBodies.forEach(body => {
            if (body.bodyRadius > 0) {
                this.renderCelestialBody(body, 0x808080, false);
            }
        });
        
        console.log(`Rendered ${this.celestialBodies.length} celestial bodies`);
    }
    
    // Helper methods for refined celestial body rendering
    private renderStar(star: ObjectContainer): void {
        const scaledRadius = Math.max(
            star.bodyRadius * EnhancedNavigationHUD.SCALE_FACTOR * 2,
            EnhancedNavigationHUD.PLANET_MIN_SIZE * 3
        );
        
        const geometry = new THREE.SphereGeometry(scaledRadius, 32, 32);
        const material = new THREE.MeshBasicMaterial({
            color: 0xffff80,
            emissive: 0xffaa00,
            emissiveIntensity: 1.0
        });
        
        const starMesh = new THREE.Mesh(geometry, material);
        const position = this.worldToSceneCoords({
            x: star.posX, 
            y: star.posY, 
            z: star.posZ
        });
        
        starMesh.position.copy(position);
        this.scene.add(starMesh);
        this.celestialBodies.push(starMesh);
        
        // Add light source at star position
        const light = new THREE.PointLight(0xffffee, 1.5, 0);
        light.position.copy(position);
        this.scene.add(light);
        
        // Add bloom/glow effect for star
        const starGlow = this.createGlowMesh(starMesh, 0xffffaa, 1.5);
        this.scene.add(starGlow);
        
        this.addLabel(position, star.name, 0xffffaa);
    }
    
    private renderCelestialBody(
        body: ObjectContainer, 
        color: number, 
        isPlanet: boolean
    ): void {
        // Calculate appropriate scale with min/max constraints
        const scaledRadius = Math.min(
            Math.max(
                body.bodyRadius * EnhancedNavigationHUD.SCALE_FACTOR,
                isPlanet ? 
                    EnhancedNavigationHUD.PLANET_MIN_SIZE : 
                    EnhancedNavigationHUD.PLANET_MIN_SIZE * 0.5
            ),
            isPlanet ? 10.0 : 5.0 // Maximum size constraints
        );
        
        // Create optimized geometry with LOD based on distance
        const detail = isPlanet ? 32 : 16;
        const geometry = new THREE.SphereGeometry(scaledRadius, detail, detail);
        
        // Material with physically-based rendering properties
        const material = new THREE.MeshStandardMaterial({
            color: color,
            roughness: 0.8,
            metalness: 0.1,
            flatShading: !isPlanet
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        const position = this.worldToSceneCoords({
            x: body.posX,
            y: body.posY,
            z: body.posZ
        });
        
        mesh.position.copy(position);
        this.scene.add(mesh);
        this.celestialBodies.push(mesh);
        
        // Add name label only for planets and significant bodies
        if (isPlanet || body.bodyRadius > 100000) {
            this.addLabel(position, body.name, 0xffffff);
        }
        
        // Add orbital reference indicators for planets
        if (isPlanet) {
            this.addOrbitalIndicator(position, scaledRadius * 1.2);
        }
    }
    
    private renderOrbitalPath(
        body: ObjectContainer, 
        parentBody: ObjectContainer | undefined
    ): void {
        if (!parentBody) return;
        
        // Calculate orbital parameters
        const parentPos = {
            x: parentBody.posX,
            y: parentBody.posY,
            z: parentBody.posZ
        };
        
        const bodyPos = {
            x: body.posX,
            y: body.posY,
            z: body.posZ
        };
        
        const orbitalDistance = this.calcDistance3d(parentPos, bodyPos);
        const scaledDistance = orbitalDistance * EnhancedNavigationHUD.SCALE_FACTOR;
        
        // Create orbital path
        const orbitGeometry = new THREE.RingGeometry(
            scaledDistance - 0.025,
            scaledDistance + 0.025,
            64
        );
        
        const orbitMaterial = new THREE.MeshBasicMaterial({
            color: body.cont_type === 'Planet' ? 0x4080ff : 0x80c0ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.3,
            depthWrite: false // Prevents z-fighting
        });
        
        const orbitMesh = new THREE.Mesh(orbitGeometry, orbitMaterial);
        
        // Position at parent center
        const parentScenePos = this.worldToSceneCoords(parentPos);
        orbitMesh.position.copy(parentScenePos);
        
        // Calculate orbital plane alignment
        // This is a simplified calculation - proper calculation would use
        // orbital mechanics parameters if available
        const orbitNormal = new THREE.Vector3(
            bodyPos.x - parentPos.x,
            bodyPos.y - parentPos.y,
            bodyPos.z - parentPos.z
        ).normalize();
        
        // Align orbit ring with orbital plane
        const rotationMatrix = new THREE.Matrix4();
        rotationMatrix.lookAt(
            new THREE.Vector3(0, 0, 0),
            orbitNormal,
            new THREE.Vector3(0, 1, 0)
        );
        
        orbitMesh.setRotationFromMatrix(rotationMatrix);
        
        this.scene.add(orbitMesh);
    }
    
    // Create a glow effect mesh for stars
    private createGlowMesh(
        mesh: THREE.Mesh, 
        glowColor: number, 
        size: number
    ): THREE.Mesh {
        const glowGeometry = new THREE.SphereGeometry(
            (mesh.geometry as THREE.SphereGeometry).parameters.radius * size,
            16, 16
        );
        
        const glowMaterial = new THREE.ShaderMaterial({
            uniforms: {
                glowColor: { value: new THREE.Color(glowColor) },
                viewVector: { value: new THREE.Vector3() }
            },
            vertexShader: `
                uniform vec3 viewVector;
                varying float intensity;
                void main() {
                    vec3 vNormal = normalize(normal);
                    intensity = pow(1.0 - abs(dot(vNormal, viewVector)), 2.0);
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `,
            fragmentShader: `
                uniform vec3 glowColor;
                varying float intensity;
                void main() {
                    gl_FragColor = vec4(glowColor, intensity * 0.5);
                }
            `,
            side: THREE.BackSide,
            blending: THREE.AdditiveBlending,
            transparent: true,
            depthWrite: false
        });
        
        const glowMesh = new THREE.Mesh(glowGeometry, glowMaterial);
        glowMesh.position.copy(mesh.position);
        
        return glowMesh;
    }
    
    // Determine current system from navigation data
    private determineCurrentSystem(): string {
        if (!this.navigationPlan) return "Stanton"; // Default
        
        // Extract system information from navigation plan
        if (this.navigationPlan.segments.length > 0) {
            const firstSegment = this.navigationPlan.segments[0];
            
            // Check origin container
            if (this.navigationPlan.originContainer) {
                const systemName = this.extractSystemName(
                    this.navigationPlan.originContainer.name
                );
                if (systemName) return systemName;
            }
            
            // Check first segment origin
            const originSystem = this.extractSystemName(firstSegment.from.name);
            if (originSystem) return originSystem;
            
            // Check destination
            const lastSegment = this.navigationPlan.segments[
                this.navigationPlan.segments.length - 1
            ];
            const destSystem = this.extractSystemName(lastSegment.to.name);
            if (destSystem) return destSystem;
        }
        
        return "Stanton"; // Default fallback
    }
    
    private extractSystemName(locationName: string): string | null {
        // Known star systems
        const systems = ["Stanton", "Pyro", "Nyx", "Terra", "Odin"];
        
        // Check if the name contains a system identifier
        for (const system of systems) {
            if (locationName.includes(system)) {
                return system;
            }
        }
        
        return null;
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
     * Render the navigation path in 3D space
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
                        EnhancedNavigationHUD.WAYPOINT_SIZE * 1.5
                    );
                }
            }
            
            // Process each segment
            segments.forEach((segment, index) => {
                // Add segment point
                const segmentPos = this.worldToSceneCoords(segment.to.position);
                points.push(segmentPos);
                
                // Add waypoint marker with appropriate color
                const isDestination = index === segments.length - 1;
                const isObstruction = segment.isObstructionBypass;
                
                const color = isDestination ? EnhancedNavigationHUD.DESTINATION_COLOR :
                            isObstruction ? EnhancedNavigationHUD.OBSTRUCTION_COLOR :
                            EnhancedNavigationHUD.WAYPOINT_COLOR;
                            
                const size = isDestination ? 
                    EnhancedNavigationHUD.WAYPOINT_SIZE * 1.5 : 
                    EnhancedNavigationHUD.WAYPOINT_SIZE;
                    
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
            
            // Create the path line with multi-segment coloring
            const pathMaterial = new THREE.LineBasicMaterial({
                vertexColors: true,
                linewidth: 2
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
            
            // Center camera on the navigation path
            this.centerCameraOnPath(points);
            
            console.log(`Path rendering complete with ${points.length} points`);
            
        } catch (error) {
            console.error("Error rendering navigation path:", error);
        }
    }
    
    /**
     * Add a waypoint marker with label
     */
    private addWaypoint(
        position: THREE.Vector3,
        name: string,
        color: number,
        size: number
    ): void {
        // Create sphere for waypoint
        const geometry = new THREE.SphereGeometry(size, 16, 16);
        const material = new THREE.MeshBasicMaterial({ color });
        const waypoint = new THREE.Mesh(geometry, material);
        waypoint.position.copy(position);
        
        // Add to scene and tracking array
        this.scene.add(waypoint);
        this.waypoints.push(waypoint);
        
        // Add text label
        this.addLabel(position, name, color);
    }
    
    /**
     * Add a text label to a 3D position
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
        
        // Update plan and render
        this.navigationPlan = newPlan;
        this.renderNavigationPath();
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
            
            // Profile frame time
            performance.mark('frame-start');
            
            // Apply frustum culling optimization
            this.updateFrustumCulling();
            
            // Only update controls if there's user interaction
            if (this.controlsNeedUpdate) {
                this.controls.update();
                this.controlsNeedUpdate = false;
            }
            
            // Optimize animation by skipping frames
            if (timestamp - this.lastAnimationTime > 100) { // 10 FPS for animations
                this.updateAnimations();
                this.lastAnimationTime = timestamp;
            }
            
            // Calculate frame time
            const frameTime = timestamp - this.lastRenderTime;
            this.lastRenderTime = timestamp;
            
            // Detect slow frames
            if (frameTime > 100) { // More than 100ms (less than 10 FPS)
                console.warn(`Slow frame detected: ${frameTime.toFixed(2)}ms (${(1000 / frameTime).toFixed(1)} FPS)`);
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
    
    // Add frustum culling to improve performance
    private updateFrustumCulling(): void {
        // Compute frustum matrix for visibility culling
        this.camera.updateMatrix();
        this.camera.updateMatrixWorld();
        
        const frustum = new THREE.Frustum();
        const projScreenMatrix = new THREE.Matrix4();
        
        projScreenMatrix.multiplyMatrices(
            this.camera.projectionMatrix,
            this.camera.matrixWorldInverse
        );
        
        frustum.setFromProjectionMatrix(projScreenMatrix);
        
        // Apply frustum culling to all celestial bodies
        this.celestialBodies.forEach(body => {
            // Skip if body is not a mesh
            if (!(body instanceof THREE.Mesh)) return;
            
            // Calculate bounding sphere
            if (!body.geometry.boundingSphere) {
                body.geometry.computeBoundingSphere();
            }
            
            // Use bounding sphere for frustum culling
            const boundingSphere = body.geometry.boundingSphere.clone();
            boundingSphere.applyMatrix4(body.matrixWorld);
            
            // Set visibility based on frustum containment
            body.visible = frustum.intersectsSphere(boundingSphere);
        });
    }
    
    // Implement progressive quality degradation for performance recovery
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
    
    private simplifyGeometries(): void {
        this.scene.traverse(object => {
            if (object instanceof THREE.Mesh) {
                if (object.geometry instanceof THREE.SphereGeometry) {
                    // Get current parameters
                    const params = (object.geometry as THREE.SphereGeometry).parameters;
                    
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
            }
        });
    }
    
    private disableNonEssentialObjects(): void {
        // Hide orbital indicators and other decorative elements
        this.scene.traverse(object => {
            if (object instanceof THREE.Mesh) {
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