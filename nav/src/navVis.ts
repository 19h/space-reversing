import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { NavigationPlan, PathSegment } from './navPlan';
import { ObjectContainer, Vector3 } from './types';

/**
 * Advanced 3D navigation path visualization for space navigation
 */
export class NavigationHUD {
    private scene: THREE.Scene;
    private camera: THREE.PerspectiveCamera;
    private renderer: THREE.WebGLRenderer;
    private controls: OrbitControls;
    
    // Navigation elements
    private navPath: THREE.Line | null = null;
    private waypoints: THREE.Mesh[] = [];
    private celestialBodies: THREE.Mesh[] = [];
    private segmentLabels: THREE.Sprite[] = [];
    
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
    private static readonly SCALE_FACTOR = 1e-8; // Scale down astronomical distances
    private static readonly PLANET_MIN_SIZE = 0.5; // Minimum visible size for planets
    private static readonly WAYPOINT_SIZE = 0.2; // Size of waypoint markers
    
    /**
     * Initialize the 3D visualization renderer
     */
    constructor(
        private container: HTMLElement,
        private navigationPlan: NavigationPlan | null,
        private celestialBodiesData: ObjectContainer[]
    ) {
        // Initialize Three.js components
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x000015); // Dark space background
        
        this.camera = new THREE.PerspectiveCamera(
            70, // FOV
            container.clientWidth / container.clientHeight, // Aspect ratio
            0.01, // Near clipping plane
            10000 // Far clipping plane (adjusted for scaled distances)
        );
        this.camera.position.z = 15;
        
        this.renderer = new THREE.WebGLRenderer({ antialias: true });
        this.renderer.setSize(container.clientWidth, container.clientHeight);
        this.renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(this.renderer.domElement);
        
        // Add orbit controls for camera manipulation
        this.controls = new OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.05;
        
        // Add lighting
        this.setupLighting();
        
        // Render the scene
        this.renderScene();
        
        // Setup resize handler
        window.addEventListener('resize', this.onWindowResize.bind(this));
        
        // Render the navigation path if available
        if (navigationPlan) {
            this.renderNavigationPath();
        }
        
        // Add celestial bodies
        this.renderCelestialBodies();
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
        const pointLight = new THREE.PointLight(0xffffdd, 1, 100);
        pointLight.position.set(0, 0, 0);
        this.scene.add(pointLight);
    }
    
    /**
     * Handle window resize events to maintain aspect ratio
     */
    private onWindowResize(): void {
        this.camera.aspect = this.container.clientWidth / this.container.clientHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    }
    
    /**
     * Convert astronomical coordinates to scene coordinates
     */
    private worldToSceneCoords(pos: Vector3): THREE.Vector3 {
        return new THREE.Vector3(
            pos.x * NavigationHUD.SCALE_FACTOR,
            pos.z * NavigationHUD.SCALE_FACTOR, // Y-up in Three.js, so using z for up
            pos.y * NavigationHUD.SCALE_FACTOR
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
                body.bodyRadius * NavigationHUD.SCALE_FACTOR,
                NavigationHUD.PLANET_MIN_SIZE
            );
            
            // Create geometry and material
            const geometry = new THREE.SphereGeometry(scaledRadius, 32, 32);
            const material = new THREE.MeshStandardMaterial({
                color: body.cont_type === 'Planet' ? 
                    NavigationHUD.PLANET_COLOR : 
                    NavigationHUD.MOON_COLOR,
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
        });
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
        if (!this.navigationPlan || this.navigationPlan.segments.length === 0) {
            return;
        }
        
        // Create path points
        const points: THREE.Vector3[] = [];
        const segments = this.navigationPlan.segments;
        
        // Add origin point
        const originPos = this.worldToSceneCoords(segments[0].from.position);
        points.push(originPos);
        
        // Create origin marker
        this.addWaypoint(
            originPos,
            segments[0].from.name,
            NavigationHUD.ORIGIN_COLOR,
            NavigationHUD.WAYPOINT_SIZE * 1.5
        );
        
        // Process each segment
        segments.forEach((segment, index) => {
            // Add segment point
            const segmentPos = this.worldToSceneCoords(segment.to.position);
            points.push(segmentPos);
            
            // Add waypoint marker with appropriate color
            const isDestination = index === segments.length - 1;
            const isObstruction = segment.isObstructionBypass;
            
            const color = isDestination ? NavigationHUD.DESTINATION_COLOR :
                          isObstruction ? NavigationHUD.OBSTRUCTION_COLOR :
                          NavigationHUD.WAYPOINT_COLOR;
                          
            const size = isDestination ? 
                NavigationHUD.WAYPOINT_SIZE * 1.5 : 
                NavigationHUD.WAYPOINT_SIZE;
                
            this.addWaypoint(segmentPos, segment.to.name, color, size);
            
            // Create segment label
            const midpoint = new THREE.Vector3().addVectors(
                points[index],
                segmentPos
            ).multiplyScalar(0.5);
            
            const distance = (segment.distance / 1000).toFixed(1);
            const type = segment.travelType === 'quantum' ? 'QT' : 'SL';
            
            this.addSegmentLabel(
                midpoint,
                `${distance} km (${type})`,
                segment.travelType === 'quantum' ? 
                    NavigationHUD.QUANTUM_PATH_COLOR : 
                    NavigationHUD.SUBLIGHT_PATH_COLOR
            );
        });
        
        // Create the path line
        const geometry = new THREE.BufferGeometry().setFromPoints(points);
        
        // Use multi-colored line segments based on travel type
        const materials = segments.map(segment => 
            new THREE.LineBasicMaterial({
                color: segment.travelType === 'quantum' ? 
                    NavigationHUD.QUANTUM_PATH_COLOR : 
                    NavigationHUD.SUBLIGHT_PATH_COLOR,
                linewidth: segment.travelType === 'quantum' ? 3 : 1,
            })
        );
        
        // Create a line group with segments
        this.navPath = new THREE.Line(geometry, materials[0]);
        this.scene.add(this.navPath);
        
        // Center camera on the navigation path
        this.centerCameraOnPath(points);
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
        if (!context) return;
        
        canvas.width = 256;
        canvas.height = 128;
        
        // Draw text
        context.font = 'Bold 20px Arial';
        context.fillStyle = '#ffffff';
        context.textAlign = 'center';
        context.fillText(text, 128, 64);
        
        // Create sprite from canvas
        const texture = new THREE.CanvasTexture(canvas);
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
        if (!context) return;
        
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
        // Calculate bounding box
        const box = new THREE.Box3().setFromPoints(points);
        const center = new THREE.Vector3();
        box.getCenter(center);
        
        // Calculate appropriate distance
        const size = new THREE.Vector3();
        box.getSize(size);
        const maxDim = Math.max(size.x, size.y, size.z);
        const distance = maxDim * 2;
        
        // Position camera
        this.camera.position.set(center.x, center.y + distance, center.z);
        this.controls.target.copy(center);
        this.controls.update();
    }
    
    /**
     * Update path visualization with new navigation plan
     */
    public updateNavigationPlan(newPlan: NavigationPlan): void {
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
     * Animation loop
     */
    private renderScene(): void {
        requestAnimationFrame(this.renderScene.bind(this));
        
        // Update controls
        this.controls.update();
        
        // Rotate waypoints for visibility
        this.waypoints.forEach(waypoint => {
            waypoint.rotation.y += 0.01;
        });
        
        // Render scene
        this.renderer.render(this.scene, this.camera);
    }
    
    /**
     * Clean up resources
     */
    public dispose(): void {
        // Remove event listeners
        window.removeEventListener('resize', this.onWindowResize.bind(this));
        
        // Dispose of Three.js resources
        this.renderer.dispose();
        this.container.removeChild(this.renderer.domElement);
    }
}
