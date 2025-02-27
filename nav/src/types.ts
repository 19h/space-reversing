import { CoordinateTransformer } from "./navPlanUtils";

// Core data structures
export interface Vector3 {
    x: number;
    y: number;
    z: number;
}

export enum System {
    Stanton = "Stanton",
    Pyro = "Pyro",
    Nyx = "Nyx",
    Ellis = "Ellis",
    Sol = "Sol",
    // ...
}

export type SystemConst = "Stanton" | "Pyro" | "Nyx" | "Ellis" | "Sol";

// Enum for Object Container types
export enum ContainerType {
    JumpPoint = "JumpPoint",
    Lagrange = "Lagrange",
    Moon = "Moon",
    NavalStation = "NavalStation",
    Planet = "Planet",
    RefineryStation = "RefineryStation",
    RestStop = "RestStop",
    Star = "Star"
}

// Enum for Point of Interest types
export enum PoiType {
    AnimalArea = "AnimalArea",
    AsteroidBelt = "AsteroidBelt",
    Cave = "Cave",
    ColonialBunker = "ColonialBunker",
    ColonialOutpost = "ColonialOutpost",
    CommArray = "CommArray",
    DerelictOutpost = "DerelictOutpost",
    DerelictSettlement = "DerelictSettlement",
    DistributionCenter = "DistributionCenter",
    Druglab = "Druglab",
    Easteregg = "Easteregg",
    Event = "Event",
    ForwardOperatingBase = "ForwardOperatingBase",
    JumpPoint = "JumpPoint",
    LandingZone = "LandingZone",
    Missing = "missing",
    MissionArea = "MissionArea",
    ObjectContainer = "ObjectContainer",
    OrbitalStation = "OrbitalStation",
    Outpost = "Outpost",
    Picoball = "Picoball",
    Prison = "Prison",
    Racetrack = "Racetrack",
    RacetrackCommunity = "RacetrackCommunity",
    River = "River",
    Scrapyard = "Scrapyard",
    Spaceport = "Spaceport",
    StashHouse = "Stash House",
    UndergroundFacility = "UndergroundFacility",
    Unknown = "Unknown",
    Wreck = "Wreck"
}

export interface PointOfInterest {
    id: number;
    name: string;
    system: string;
    objContainer?: string | null;  // Planet/moon name, null if in space
    poiType: PoiType;               // Use the enum
    class: string;
    posX: number;
    posY: number;
    posZ: number;
    hasQTMarker: boolean;

    dateAdded?: string | null;
    comment?: string | null;
    withVersion?: string | null;
}

export interface ObjectContainer {
    id: number;
    system: System;
    cont_type: ContainerType;      // Use the enum
    name: string;
    internalName: string;
    posX: number;
    posY: number;
    posZ: number;
    rotVelX: number;
    rotVelY: number;
    rotVelZ: number;
    rotAdjX: number;
    rotAdjY: number;
    rotAdjZ: number;
    rotQuatW: number;
    rotQuatX: number;
    rotQuatY: number;
    rotQuatZ: number;
    bodyRadius: number;
    omRadius: number;
    gridRadius: number;
}

/**
 * Transform POI coordinates with enhanced celestial body positional correction
 * Ensures all coordinates are returned in global space (meters)
 */
export const getCoordinates = (
    poi: PointOfInterest,
    containers: ObjectContainer[],
): Vector3 => {
    // Direct coordinate handling for absolute coordinates
    if (poi.hasQTMarker || !poi.objContainer) {
        return {
            x: poi.posX,
            y: poi.posY,
            z: poi.posZ
        };
    }
    
    // Locate parent celestial body
    const container =
        containers.find(c => c.name === poi.objContainer);
    
    if (!container) {
        console.error(`Astronomical reference frame '${poi.objContainer}' not found for entity '${poi.name}'`);
        // Fallback: treat as absolute coordinates
        return {
            x: poi.posX,
            y: poi.posY,
            z: poi.posZ
        };
    }
    
    // Create local coordinate vector (usually in kilometers)
    const localPos: Vector3 = {
        x: poi.posX,
        y: poi.posY,
        z: poi.posZ
    };
    
    // Transform to global coordinates with proper unit conversion
    return CoordinateTransformer.transformCoordinates(
        localPos,
        container,
        'toGlobal'
    );
}

export interface NavigationResult {
    distance: number;          // Total distance in meters
    direction: {
        pitch: number;           // Vertical angle in degrees 
        roll: number;            // Roll angle in degrees
        yaw: number;             // Horizontal angle in degrees
    };
    eta: number;               // Estimated time of arrival in seconds
    angularDeviation?: number | undefined; // Angle between current trajectory and destination
    closestOrbitalMarker?: {   // Nearest orbital marker if POI is on a planetary body
        name: string;
        distance: number;
    } | undefined;
    closestQTBeacon?: {        // Nearest quantum travel beacon
        name: string;
        distance: number;
    } | undefined;
}