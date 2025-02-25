struct CActorEntity 
{
    // [0x0000 - 0x0183] Core Memory Layout
    void*               vtable;                    // 0x0000
    uint64_t            entityId;                  // 0x0008
    struct AABB {                                  // 0x0010
        struct Vec3d {                             // 0x0010
            double      x;                         // 0x0010
            double      y;                         // 0x0018
            double      z;                         // 0x0020
        } min;                                     // 0x0028 (end)
        struct Vec3d {                             // 0x0028
            double      x;                         // 0x0028
            double      y;                         // 0x0030
            double      z;                         // 0x0038
        } max;                                     // 0x0040 (end)
    } worldBounds;                                 // 0x0040 (end)
    
    // [0x0184 - 0x018F] Entity Reference Linkage
    IEntityPtr          pOwnerEntity;              // 0x0184
    PhysicalEntityLink* pPhysicalEntityLinks;      // 0x018C
    
    // [0x0190 - 0x01FF] Spatial Transform 
    struct Matrix33 {                              // 0x0190
        float           m00, m01, m02;             // 0x0190, 0x0194, 0x0198
        float           m10, m11, m12;             // 0x019C, 0x01A0, 0x01A4
        float           m20, m21, m22;             // 0x01A8, 0x01AC, 0x01B0
        // 16-byte alignment padding               // 0x01B4-0x01BF
    } orientationMatrix;                           // 0x01C0 (end)
    
    struct Vec3d {                                 // 0x01C0
        double          x;                         // 0x01C0
        double          y;                         // 0x01C8
        double          z;                         // 0x01D0
    } position;                                    // 0x01D8 (end)
    
    struct Quat {                                  // 0x01D8
        float           x;                         // 0x01D8
        float           y;                         // 0x01DC
        float           z;                         // 0x01E0
        float           w;                         // 0x01E4
    } orientation;                                 // 0x01E8 (end)
    
    float               scale;                     // 0x01E8
    // 8-byte alignment padding                    // 0x01EC-0x01FF
    
    // [0x0200 - 0x0235] Synchronization
    struct SpinLock {                              // 0x0200
        volatile int64_t lockValue;                // 0x0200
        uint32_t        ownerThreadId;             // 0x0208
        uint32_t        recursionCount;            // 0x020C
        // Implementation-specific fields           // 0x0210-0x0235
    } lockUpdate;                                  // 0x0236 (end)
    
    // [0x0236 - 0x023F] Spatial Partitioning
    int16_t             gridCellX;                 // 0x0236
    int16_t             gridCellY;                 // 0x0238
    // 4-byte alignment padding                    // 0x023A-0x023F
    
    // [0x0240 - 0x03BF] Entity Configuration
    uint32_t            physicalEntityType;        // 0x0244
    uint32_t            partitionMask;             // 0x0248
    // Configuration parameters and flags          // 0x024C-0x03BF
    
    // [0x03C0 - 0x03FF] Kinematic State
    struct Vec3 {                                  // 0x03C0
        float           x;                         // 0x03C0
        float           y;                         // 0x03C4
        float           z;                         // 0x03C8
    } linearVelocity;                              // 0x03CC (end)
    
    struct Vec3 {                                  // 0x03CC
        float           x;                         // 0x03CC
        float           y;                         // 0x03D0
        float           z;                         // 0x03D4
    } cachedVelocity;                              // 0x03D8 (end)
    
    struct Vec3 {                                  // 0x03D8
        float           x;                         // 0x03D8
        float           y;                         // 0x03DC
        float           z;                         // 0x03E0
    } angularVelocity;                             // 0x03E4 (end)
    
    float               angularSpeed;              // 0x03E4
    
    struct Vec3 {                                  // 0x03F0
        float           x;                         // 0x03F0
        float           y;                         // 0x03F4
        float           z;                         // 0x03F8
    } externalAcceleration;                        // 0x03FC (end)
    
    float               sleepTimerDt;              // 0x03FC
    
    // [0x0400 - 0x048F] Force Accumulation & Inertial Properties
    struct Vec3 {                                  // 0x0420
        float           x;                         // 0x0420
        float           y;                         // 0x0424
        float           z;                         // 0x0428
    } totalForce;                                  // 0x042C (end)
    
    struct Vec3 {                                  // 0x042C
        float           x;                         // 0x042C
        float           y;                         // 0x0430
        float           z;                         // 0x0434
    } totalTorque;                                 // 0x0438 (end)
    
    struct Vec3_tpl_double {                       // 0x0438
        double          x;                         // 0x0438
        double          y;                         // 0x0440
        double          z;                         // 0x0448
    } impulseForce;                                // 0x0450 (end)
    
    // Additional force accumulation fields        // 0x0450-0x0477
    
    struct DiagInertiaMatrix {                     // 0x0478
        float           xx;                        // 0x0478
        float           yy;                        // 0x047C
        float           zz;                        // 0x0480
        // 4-byte alignment padding                // 0x0484
    } inertiaTensor;                               // 0x0484 (end)
    
    float               invMass;                   // 0x0484
    float               mass;                      // 0x0488
    // 8-byte alignment padding                    // 0x048C-0x048F
    
    // [0x0490 - 0x04CF] Simulation Parameters
    float               sleepSpeedThreshold;       // 0x0490
    // SIMD-aligned simulation parameters          // 0x0494-0x049B
    float               maxTimeStep;               // 0x049C
    float               dampingRatio;              // 0x04A0
    // Additional simulation parameters            // 0x04A4-0x04B3
    float               frictionCoeff;             // 0x04B4
    float               restitutionCoeff;          // 0x04B8
    float               contactHardness;           // 0x04BC
    // 16-byte alignment padding                   // 0x04C0-0x04C7
    
    struct Vec4 {                                  // 0x04C8
        float           x;                         // 0x04C8
        float           y;                         // 0x04CC
        float           z;                         // 0x04D0
        float           w;                         // 0x04D4
    } simulationBounds;                            // 0x04D8 (end)
    
    // [0x0520 - 0x06FF] Collision System
    uint32_t            flags;                     // 0x0520
    
    struct CollisionFilterData {                   // 0x0524
        uint16_t        physicalFlags;             // 0x0524
        uint16_t        physicalFlagsOR;           // 0x0526
        uint16_t        partIds[2];                // 0x0528, 0x052A
        uint16_t        partIdsOR[2];              // 0x052C, 0x052E
        uint8_t         flagsGroupDst;             // 0x0530
        uint8_t         flagsGroupSrc;             // 0x0531
        uint16_t        ignoreCollisionGroupDst;   // 0x0532
        uint16_t        ignoreCollisionGroupSrc;   // 0x0534
        uint16_t        partIds1[2];               // 0x0536, 0x0538
        uint16_t        partIds1OR[2];             // 0x053A, 0x053C
        uint8_t         padding[2];                // 0x053E-0x053F
    } collisionFilterData;                         // 0x0540 (end)
    
    // 16-byte alignment padding                   // 0x0540-0x0551
    ContactManager*     pContactManager;           // 0x0552
    
    struct CollisionGeometry {                     // 0x0560
        void*           pGeometryVTable;           // 0x0560
        uint32_t        geometryType;              // 0x0568
        uint32_t        primitiveCount;            // 0x056C
        void*           pImplementationData;       // 0x0570
        // Additional geometry data                // 0x0578-0x0583
    }* pCollisionGeometry;                         // 0x0584 (end)
    
    uint64_t**          ppCollisionFilters;        // 0x0584
    
    struct ContactData {                           // 0x0624
        uint32_t        contactCount;              // 0x0624
        uint32_t        contactCapacity;           // 0x0628
        struct Contact {                           // Array at 0x0630
            Vec3        point;                     // +0x00
            Vec3        normal;                    // +0x0C
            float       penetration;               // +0x18
            uint16_t    materialIdSrc;             // +0x1C
            uint16_t    materialIdDst;             // +0x1E
            uint32_t    featureIdSrc;              // +0x20
            uint32_t    featureIdDst;              // +0x24
            // 32-bit alignment padding            // +0x28-+0x2F
        }* pContacts;                              // 0x0630
        // Additional contact management data      // 0x0638-0x06FF
    }* pContactSurfaces;                           // 0x0700 (end)
    
    // [0x0700 - 0x0937] Physics World Integration
    struct IPhysicalWorld {                        // 0x0704
        void*           pWorldVTable;              // 0x0704
        // Physics world implementation data       // 0x070C-0x0937
    }* pPhysWorld;                                 // 0x0938 (end)
    
    // [0x0938 - 0x096F] Continuous Collision Detection
    struct ContactTrailSystem {                    // 0x0938
        struct Vec3 {                              // 0x0938
            float       x;                         // 0x0938
            float       y;                         // 0x093C
            float       z;                         // 0x0940
        } contactNormal;                           // 0x0944 (end)
        
        struct Vec3 {                              // 0x0944
            float       x;                         // 0x0944
            float       y;                         // 0x0948
            float       z;                         // 0x094C
        } trailOrientation;                        // 0x0950 (end)
        
        struct Vec3 {                              // 0x0950
            float       x;                         // 0x0950
            float       y;                         // 0x0954
            float       z;                         // 0x0958
        } trailDirection;                          // 0x095C (end)
        
        float           trailSphereDistance;       // 0x095C
        float           minTimeStep;               // 0x0960
        float           restStateThreshold;        // 0x0964
        float           velocityEpsilon;           // 0x0968
        float           restAccumulator;           // 0x096C
    } contactTrailSystem;                          // 0x0970 (end)
    
    // [0x0970 - 0x09FF] Contact Parameters & Force State
    struct Vec3 {                                  // 0x0972
        float           x;                         // 0x0972
        float           y;                         // 0x0976
        float           z;                         // 0x097A
    } forceAccumulator;                            // 0x097E (end)
    
    struct ContactParams {                         // 0x0980
        float           restVelocityThreshold;     // 0x0980
        float           maxAngularVelocity;        // 0x0984
        // SIMD-aligned parameter block            // 0x0988-0x0990
        float           minFrictionImpulse;        // 0x0994
        // Additional contact parameters           // 0x0998-0x09FF
    } contactParams;                               // 0x0A00 (end)
    
    // [0x0A38 - 0x0B00] Ground Detection & Debug Visualization
    union {                                        // 0x0A38
        struct GroundInfo {                        // 0x0A38
            struct Vec3d {                         // 0x0A38
                double  x;                         // 0x0A38
                double  y;                         // 0x0A40
                double  z;                         // 0x0A48
            } groundPos;                           // 0x0A50 (end)
            
            struct Vec3d {                         // 0x0A50
                double  x;                         // 0x0A50
                double  y;                         // 0x0A58
                double  z;                         // 0x0A60
            } groundNormal;                        // 0x0A68 (end)
            
            union {                                // 0x0A80
                double  penetrationDepth;          // 0x0A80
                double  debugVelocityThreshold;    // 0x0A80
            };                                     // 0x0A88 (end)
            
            union {                                // 0x0A88
                double  frictionCoeff;             // 0x0A88
                double  debugAccelerationThreshold; // 0x0A88
            };                                     // 0x0A90 (end)
            
            union {                                // 0x0A90
                double  restitutionCoeff;          // 0x0A90
                double  debugPenetrationThreshold; // 0x0A90
            };                                     // 0x0A98 (end)
            
            // 64-bit alignment padding            // 0x0A98-0x0AD7
            
            struct Vec3d {                         // 0x0AD8
                double  x;                         // 0x0AD8
                double  y;                         // 0x0AE0
                double  z;                         // 0x0AE8
            } contactPoint;                        // 0x0AF0 (end)
            
            struct Vec3d {                         // 0x0AF0
                double  x;                         // 0x0AF0
                double  y;                         // 0x0AF8
                double  z;                         // 0x0B00
            } contactNormal;                       // 0x0B08 (end)
            
            uint64_t    surfaceMaterialId;         // 0x0B08
        };                                         // 0x0B10 (end)
        
        struct DebugInfo {                         // 0x0A38
            struct Vec3d {                         // 0x0A38
                double  x;                         // 0x0A38
                double  y;                         // 0x0A40
                double  z;                         // 0x0A48
            } __groundPos;                         // 0x0A50 (end)
            
            struct Vec3d {                         // 0x0A50
                double  x;                         // 0x0A50
                double  y;                         // 0x0A58
                double  z;                         // 0x0A60
            } __groundNormal;                      // 0x0A68 (end)
            
            struct DebugVisualizationState {       // 0x0A68
                struct Vec3d {                     // 0x0A68
                    double x;                      // 0x0A68
                    double y;                      // 0x0A70
                    double z;                      // 0x0A78
                } visualizationMinExtent;          // 0x0A80 (end)
                
                struct Vec3d {                     // 0x0A80
                    double x;                      // 0x0A80
                    double y;                      // 0x0A88
                    double z;                      // 0x0A90
                } visualizationMaxExtent;          // 0x0A98 (end)
                
                double  debugVelocityThreshold;    // 0x0A98
                double  debugAccelerationThreshold;// 0x0AA0
                double  debugPenetrationThreshold; // 0x0AA8
            } debugVisualizationState;             // 0x0AB0 (end)
        };                                         // 0x0AB0 (end)
    };                                             // 0x0B00 (end)
    
    struct SpinLock {                              // 0x0B00
        volatile int64_t lockValue;                // 0x0B00
        uint32_t        ownerThreadId;             // 0x0B08
        uint32_t        recursionCount;            // 0x0B0C
        // Implementation-specific fields          // 0x0B10-0x0B1F
    } groundDebugLock;                             // 0x0B20 (end)
    
    // [0x1020 - 0x10FF] Additional Force State
    struct Vec3 {                                  // 0x1020
        float           x;                         // 0x1020
        float           y;                         // 0x1024
        float           z;                         // 0x1028
        float           w;                         // 0x102C (alignment padding)
    } impulseAccumulator;                          // 0x1030 (end)
    
    struct Vec3 {                                  // 0x1032
        float           x;                         // 0x1032
        float           y;                         // 0x1036
        float           z;                         // 0x103A
        float           w;                         // 0x103E (alignment padding)
    } angularImpulse;                              // 0x1042 (end)
    
    struct Vec3 {                                  // 0x1044
        float           x;                         // 0x1044
        float           y;                         // 0x1048
        float           z;                         // 0x104C
    } gravityAccumulator;                          // 0x1050 (end)
    
    // [0x1100 - 0x116F] Constraint System
    float               timeInactive;              // 0x1104
    // Constraint system padding and fields        // 0x1108-0x113F
    float               maxPenetration;            // 0x1140
    // Additional constraint data                  // 0x1144-0x1167
    
    struct Vec3 {                                  // 0x1168
        float           x;                         // 0x1168
        float           y;                         // 0x116C
        float           z;                         // 0x1170
    } constraintImpulse;                           // 0x1174 (end)
    
    float               maxConstraintTorque;       // 0x1172
    
    // [0x1270 - 0x17FF] Component Subsystems
    struct IActorPhysics {                         // 0x1272
        void*           pActorPhysicsVTable;       // 0x1272
        // Extensive internal state data           // 0x127A-0x1623
    }* pPhysicsComponent;                          // 0x1624 (end)
    
    struct IFoliageInteraction {                   // 0x1624
        void*           pFoliageVTable;            // 0x1624
        uint32_t        foliageInstanceCount;      // 0x162C
        uint32_t        lastUpdateFrameId;         // 0x1630
        void*           pFoliageInstances;         // 0x1634
        // Additional foliage interaction data     // 0x163C-0x1783
    }* pFoliageInteraction;                        // 0x1784 (end)
    
    struct IWaterInteraction {                     // 0x1784
        void*           pWaterVTable;              // 0x1784
        uint32_t        waterVolumeId;             // 0x178C
        float           submergedFraction;         // 0x1790
        float           waterDensity;              // 0x1794
        Vec3            waterFlowVelocity;         // 0x1798-0x17A4
        // Additional water interaction data       // 0x17A4-0x17FF
    }* pWaterInteraction;                          // 0x1800 (end)
    
    // [0x2400 - 0x242F] State Management
    uint16_t            stateFlags;                // 0x2416
    uint8_t             simulationFlags;           // 0x2418
    uint8_t             contactFlags;              // 0x2419
    // 8-byte alignment padding                    // 0x241A-0x2423
    
    struct SpinLock {                              // 0x2424
        volatile int64_t lockValue;                // 0x2424
        uint32_t        ownerThreadId;             // 0x242C
        uint32_t        recursionCount;            // 0x2430
    } lockActor;                                   // 0x2434 (end)
    
    // [0x2450 - 0x25FF] Entity Relationships
    struct AttachmentRecord {                      // 0x2452
        void*           pAttachmentVTable;         // 0x2452
        uint64_t        attachmentId;              // 0x245A
        uint32_t        attachmentFlags;           // 0x2462
        // Additional attachment data              // 0x2466-0x2551
    }* pAttachmentRecords;                         // 0x2552 (end)
    
    struct IConstraintEntity {                     // 0x2552
        void*           pConstraintVTable;         // 0x2552
        uint32_t        constraintId;              // 0x255A
        uint32_t        constraintType;            // 0x255E
        // Additional constraint entity data       // 0x2562-0x25FF
    }* pConstraintEntity;                          // 0x2600 (end)
    
    // [0x2840 - 0x286F] Dynamic Entity List
    struct DynamicEntityContainer {                // 0x2848
        struct IPhysicalEntity {                   // Pointed to by pEntities
            void*       pEntityVTable;             // +0x00
            uint64_t    entityId;                  // +0x08
            uint32_t    entityType;                // +0x10
            uint32_t    entityFlags;               // +0x14
            // Extensive entity state data         // +0x18-onwards
        }** pEntities;                             // 0x2848
        
        IPhysicalEntity** pEndMarker;              // 0x2856
        IPhysicalEntity** pCapacityMarker;         // 0x2864
    } dynamicEntityList;                           // 0x286C (end)
};