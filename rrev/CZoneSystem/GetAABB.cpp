// Zone handle representing a reference to zone objects
struct SZoneObjectHandle {
    uint32_t id;  // Format: high 8 bits = type index, mid 8 bits = generation, low 16 bits = index
    
    uint8_t GetTypeIndex() const { return (id >> 24) & 0xFF; }
};

// Content structure for zone objects
struct SZoneHandleContent {
    void* ownerThread;            // Owner thread identifier
    int32_t readLockCount;        // Reader lock counter
    const char* debugName;        // Debug identifier
    CRWLock accessCheck;          // General access lock
    CRWLock accessCheck_Transform; // Transform-specific lock
    CRWLock accessCheck_Bounds;    // Bounds-specific lock
    uint8_t nType;                // Type with BOUNDS flag in bit 5
    int32_t zoneID;               // Zone identifier
    
    // Various data fields including transforms and bounds
    // positioned at type-specific offsets
    
    enum {
        TYPE_COUNT = 5,
        BOUNDS = 0x20  // Bit 5 indicates presence of bounds
    };
};

// Zone descriptor within the system
struct SZoneDesc {
    uint64_t pZone : 48;          // Pointer to zone (48-bit)
    uint16_t zoneGeneration;      // Generation counter for safe referencing
};

// Thread-safe read-write lock implementation
class CRWLock {
private:
    static const uint32_t LOCK_MAGIC = 322375884;
    volatile int64_t lockValue;   // Lock state with reader count and flags
    uint32_t magic;               // Validation token
    const char* lockName;         // Debug identifier
    void* ownerThread;            // Writer thread identity
    int32_t recursionCount;       // Recursion tracking
    
public:
    void AcquireReadLock(const char* caller, const char* lockName);
    void ReleaseReadLock();
    bool IsLocked() const;
    int GetOwnerId() const;
    void* GetOwner() const;
};

class CZoneSystem {
private:
    CRWLock m_GlobalStateLock;    // System-wide synchronization lock
    SZoneDesc* m_Zones;           // Array of zone descriptors
    size_t m_ZoneCount;           // Number of active zones
    
    // Type-specific metadata
    void* m_pZoneHandleContents[SZoneHandleContent::TYPE_COUNT]; 
    uint16_t m_arrHandleContentSize[SZoneHandleContent::TYPE_COUNT];
    uint16_t m_arrHandleBoundsOffset[SZoneHandleContent::TYPE_COUNT];
    uint16_t m_arrHandleTransformOffset[SZoneHandleContent::TYPE_COUNT];
    
    // Internal state tracking
    uint32_t m_GlobalStateVersion;
    
public:
    // Retrieves zone handle content from handle
    SZoneHandleContent* GetZoneHandleContent(SZoneObjectHandle* handle) {
        uint8_t typeIndex = handle->GetTypeIndex();
        uint16_t contentSize = m_arrHandleContentSize[typeIndex];
        uint32_t objIndex = handle->id & 0xFFFFFF;
        uint64_t offset = contentSize * objIndex;
        
        assert((offset % contentSize) == 0);
        return (SZoneHandleContent*)(m_pZoneHandleContents[typeIndex] + offset);
    }
    
    // Obtains zone object from handle content
    CZone* GetZoneFromZoneHandle(int32_t zoneID) {
        if (zoneID == -1) return nullptr;
        
        assert(m_GlobalStateLock.IsLocked());
        uint16_t index = zoneID & 0xFFFF;
        uint16_t generation = zoneID >> 16;
        
        assert(index < m_ZoneCount);
        
        if (index && m_Zones[index].zoneGeneration != generation)
            return nullptr;
            
        assert(m_Zones[index].pZone != 0);
        assert((((CZone*)m_Zones[index].pZone)->m_nZoneID & 0xFFFF) == index);
        
        return (CZone*)m_Zones[index].pZone;
    }
    
    // Retrieves transform data for zone content
    SZoneObjectTransform* GetZoneTransform(SZoneHandleContent* content) {
        uint8_t typeIndex = content->nType & 0xF;
        assert(typeIndex < SZoneHandleContent::TYPE_COUNT);
        assert(content->accessCheck_Transform.IsLocked());
        
        return (SZoneObjectTransform*)((char*)content + 176 + 
                m_arrHandleTransformOffset[typeIndex]);
    }
    
    // Retrieves bounds data for zone content
    SZoneObjectBounds* GetZoneBounds(SZoneHandleContent* content) {
        uint8_t typeIndex = content->nType & 0xF;
        assert(typeIndex < SZoneHandleContent::TYPE_COUNT);
        assert(content->accessCheck_Bounds.IsLocked());
        
        return (SZoneObjectBounds*)((char*)content + 176 + 
                m_arrHandleBoundsOffset[typeIndex]);
    }
    
    // Primary AABB calculation function
    AABB* GetAABB(AABB* outAABB, SZoneObjectHandle* zoneHandle, int flags, 
                 uint32_t transformState);
};

AABB* CZoneSystem::GetAABB(AABB* outAABB, SZoneObjectHandle* zoneHandle, int flags, 
                         uint32_t transformState) {
    // Performance tracking
    STraceProfileSection profiler("CZoneSystem::GetAABB", 
                                  "W:\\p4-src\\CryEngine\\Code\\CryEngine\\Cry3DEngine\\ZoneSystem.cpp", 
                                  2706);
    
    // Handle invalid zone case
    if ((zoneHandle->id & 0xFFFFFF) == 0xFFFFFF) {
        outAABB->min = Vec3(FLT_MAX, 0, 0);
        outAABB->max = Vec3(-FLT_MAX, -FLT_MAX, -FLT_MAX);
        assert(profiler.IsActive());
        profiler.End();
        return outAABB;
    }
    
    // Obtain zone handle content
    SZoneHandleContent* zoneHandleContent = GetZoneHandleContent(zoneHandle);
    assert((zoneHandleContent->nType >> 4) & SZoneHandleContent::BOUNDS);
    
    // Save SIMD registers for vector operations
    SaveXMMRegisters();
    
    if (flags == 0) {  // World-space calculation
        bool isFiberContext = IsFiberContext();
        
        // Acquire global read lock if not in fiber context
        if (!isFiberContext) {
            int32_t ownerId = GetCurrentThreadId();
            assert(ownerId != -1);
            
            if (m_GlobalStateLock.GetOwnerId() == ownerId) {
                m_GlobalStateLock.IncrementRecursionCounter();
            } else {
                assert(m_GlobalStateLock.GetMagic() == 322375884);
                AcquireGlobalReadLock("CZoneSystem::GetAABB", "m_GlobalStateLock");
            }
        }
        
        // Acquire zone-specific read locks
        AcquireZoneReadLocks(zoneHandleContent);
        
        // Retrieve zone data and calculate AABB
        CZone* zone = GetZoneFromZoneHandle(zoneHandleContent->zoneID);
        SZoneObjectBounds* bounds = GetZoneBounds(zoneHandleContent);
        SZoneObjectTransform* transform = GetZoneTransform(zoneHandleContent);
        
        // Local AABB computation
        LocalAABB localAABB;
        CalculateAABB(zone, &localAABB, transform, transformState);
        
        // Transform to world space
        if (localAABB.min.z <= localAABB.max.z) {
            // Matrix transformation of AABB corners and reconstruction
            TransformAABB(localAABB, transform->matrix, transform->translation, outAABB);
        } else {
            // Invalid local bounds, use default values
            outAABB->min = Vec3(FLT_MIN, FLT_MIN, FLT_MIN);
            outAABB->max = Vec3(FLT_MAX, FLT_MAX, FLT_MAX);
        }
        
        // Release locks in reverse order
        ReleaseZoneReadLocks(zoneHandleContent);
        
        if (!isFiberContext) {
            if (m_GlobalStateLock.GetOwnerId() == GetCurrentThreadId() && 
                m_GlobalStateLock.GetRecursionCounter() > 0) {
                m_GlobalStateLock.DecrementRecursionCounter();
            } else {
                ReleaseGlobalReadLock();
            }
        }
    } else if (flags == 2) {  // Local-space calculation
        // Similar structure to flag 0 case but without world transformation
        AcquireZoneReadLocks(zoneHandleContent);
        CZone* zone = GetZoneFromZoneHandle(zoneHandleContent->zoneID);
        SZoneObjectTransform* transform = GetZoneTransform(zoneHandleContent);
        
        // Get raw local bounds
        *outAABB = *GetZoneBounds(zoneHandleContent);
        
        ReleaseZoneReadLocks(zoneHandleContent);
    } else if (flags == 3) {  // Raw bounds retrieval
        AcquireZoneReadLocks(zoneHandleContent);
        // Simply copy raw bounds without transformation
        *outAABB = *GetZoneBounds(zoneHandleContent);
        ReleaseZoneReadLocks(zoneHandleContent);
    } else {
        assert(false);  // Unsupported flag
    }
    
    // End profiling and restore registers
    assert(profiler.IsActive());
    profiler.End();
    RestoreXMMRegisters();
    
    return outAABB;
}