class CZone {
private:
    // Spatial transformation data
    Matrix44 m_localTransform;        // Local-space transformation matrix
    Matrix44 m_worldTransform;        // Cached world-space transformation
    Vec3 m_position;                  // Position vector
    Quaternion m_rotation;            // Rotation quaternion
    
    // Hierarchical linkage
    CZone* m_pParentZone;             // Parent zone reference
    
    // Concurrency protection
    CigRWLock m_accessCheck_Transform; // Transformation access lock
    
    // State tracking
    uint32_t m_nLastUpdateVersion;     // Version tracking for change detection
    uint32_t m_zoneID;                 // Unique zone identifier
    uint16_t m_typeIndex;              // Zone type classification
};

class CZoneSystem {
private:
    // Global synchronization
    CigRWLock m_GlobalStateLock;
    
    // Zone storage container
    std::vector<ZoneHandle> m_Zones;
    
    // Type-specific metadata
    uint16_t m_arrHandleContentSize[TYPE_COUNT];
    
    // State tracking
    uint32_t m_currentUpdateVersion;   // Global update version counter
};

class CigRWLock {
private:
    // Lock state with bit-field encoding:
    // - Bits 0-9: Read lock count (0-1023)
    // - Bits 10-19: Write lock count
    // - Bit 20: Write lock pending flag
    // - Bits 21+: Fiber/thread identification
    volatile int64_t m_lockState;
    
    // Owner tracking for debugging and validation
    int m_eLockOwner;       // Current owner thread identifier
    int m_nLockCount;       // Recursive lock count for reentrant locks
    
    // Diagnostic information
    const char* m_pLockName;
    
    // Integrity validation
    uint32_t m_magicNumber; // 0x13371234 (validation constant)

public:
    // Lock acquisition/release operations
    void RLock(const char* callerName);
    void RUnlock();
    void WLock(const char* callerName);
    void WUnlock();
    
    // Non-blocking acquisition attempts
    bool TryRLock(const char* callerName);
    bool TryWLock(const char* callerName);
    
    // State inspection methods
    bool IsLocked() const;
    bool IsWLocked() const;
    bool IsRLocked() const;
};

// Allocation primitives with tracing capabilities
void* CryMalloc(size_t size, int alignment = 16);
void CryFree(void* ptr);

// Vector container memory management
template<typename T>
void* GrowVector(std::vector<T>& vec, size_t newCapacity);

// String manipulation with memory optimization
void CryStringCopy(char* dest, size_t destSize, const char* src);

void CigOnFailedCodeAssert(const char* expression, const char* file, int line, const char* message) {
    // Acquire global assertion lock to prevent concurrent assertion processing
    ScopedLock<CigLock> assertLock(g_AssertLock);
    
    // Debugger integration for development environments
    if (IsDebuggerPresent()) {
        // Output diagnostic information to debug console
        OutputDebugString(FormatAssertMessage(expression, file, line, message));
        
        // Break execution for interactive debugging
        __debugbreak();
    }
    
    // Console output for headless execution contexts
    if (g_AssertLogToConsole) {
        fprintf(stdout, "Assertion failed: %s (%s:%d) - %s\n", 
                expression, file, line, message);
    }
    
    // File logging for persistent diagnostics
    if (g_AssertLogToFile) {
        fprintf(stderr, "Assertion failed: %s (%s:%d) - %s\n", 
                expression, file, line, message);
    }
    
    // Event system integration for telemetry
    if (g_pTraceEventSystem) {
        g_pTraceEventSystem->OnAssertionFailed(expression, file, line, message);
    }
    
    // Assertion counter for statistical analysis
    InterlockedIncrement(&g_AssertCounter);
}

Quaternion* CZoneSystem::GetRotation(ZoneID* zoneId, Quaternion* outRotation, int flags) {
    // Performance profiling instrumentation
    CryProfileSection profile("CZoneSystem::GetRotation");
    
    // Invalid zone ID handling - return identity quaternion
    if ((*zoneId & 0xFFFFFF) == 0xFFFFFF) {
        outRotation->SetIdentity();
        return outRotation;
    }
    
    // Retrieve zone content reference
    ZoneContent* zoneContent = GetZoneContent(zoneId);
    
    // Process based on specified retrieval flags
    if (flags == 0) {
        // Standard retrieval with full locking protocol
        ScopedGlobalStateLock globalLock(this);
        ScopedReadLock transformLock(zoneContent->accessCheck_Transform);
        
        // Retrieve zone and extract rotation data
        CZone* zone = GetZone(zoneContent->zoneID);
        Quaternion* rotation = GetZoneContentRotation(zone, zoneContent);
        
        // Copy rotation to output parameter
        *outRotation = *rotation;
        return outRotation;
    }
    else if (flags == 2) {
        // Optimized retrieval with minimal locking
        ScopedReadLock transformLock(zoneContent->accessCheck_Transform);
        Quaternion* rotation = GetZoneContentDirectRotation(zoneContent);
        *outRotation = *rotation;
        return outRotation;
    }
    else if (flags == 3) {
        // Special case - return identity quaternion
        outRotation->SetIdentity();
        return outRotation;
    }
    
    // Invalid flag value - execution should never reach this point
    assert(false);
    return outRotation;
}

void CZone::RefreshWorldSpacePosition(unsigned int flags) {
    // Global state synchronization
    ScopedGlobalStateLock globalLock(g_pZoneSystem);
    
    // Exclusive transformation access
    ScopedWriteLock transformLock(m_accessCheck_Transform);
    
    // Version-based change detection
    if (m_nLastUpdateVersion != g_pZoneSystem->GetCurrentUpdateVersion()) {
        // Update version tracking
        m_nLastUpdateVersion = flags;
        
        // Cache initial transform state
        m_cachedWorldTransform = m_localTransform;
        
        // Parent transform propagation
        if (m_pParentZone) {
            // Retrieve parent world transformation
            Matrix44 parentTransform;
            m_pParentZone->GetTransform_ws(parentTransform, flags);
            
            // Quaternion-based transformation mathematics
            Quaternion parentQuat, localQuat, resultQuat;
            parentTransform.GetRotation(parentQuat);
            m_localTransform.GetRotation(localQuat);
            
            // Combine rotations through quaternion multiplication
            resultQuat = parentQuat * localQuat;
            
            // Extract position components
            Vec3 parentPos = parentTransform.GetTranslation();
            Vec3 localPos = m_localTransform.GetTranslation();
            
            // Apply rotated local offset to parent position
            Vec3 worldPos = parentPos + parentQuat.Rotate(localPos);
            
            // Construct final world transformation matrix
            m_cachedWorldTransform.SetRotationQuaternion(resultQuat);
            m_cachedWorldTransform.SetTranslation(worldPos);
        }
        
        // Update version to current system state
        m_nLastUpdateVersion = g_pZoneSystem->GetCurrentUpdateVersion();
    }
}

void CigRWLock::RLock(const char* callerName) {
    // Thread identification for ownership tracking
    int threadId = SThreadInfoBlock::Get()->eActiveOwnerId;
    
    // Validate thread context
    if (threadId == LockOwner::NO_OWNER) {
        assert(false && "eActiveOwnerId != LockOwner::NO_OWNER");
    }
    
    // Check for recursive lock acquisition
    if (m_eLockOwner == threadId) {
        // Increment recursion counter
        m_nLockCount++;
        return;
    }
    
    // Validate lock integrity
    if (m_magicNumber != 0x13371234) {
        FatalError("Trying to interact with an invalid lock.");
    }
    
    // Attempt atomic read lock acquisition
    int64_t state = InterlockedIncrement64(&m_lockState);
    
    // Check for write lock conflicts
    if ((state & WRITE_LOCK_PENDING) != 0) {
        // Wait for write lock resolution
        WaitForRLock(m_lockState, callerName, m_pLockName);
    }
}

void CigRWLock::RUnlock() {
    // Check for recursive lock
    if (m_nLockCount > 0) {
        // Decrement recursion counter
        m_nLockCount--;
        return;
    }
    
    // Validate lock integrity
    if (m_magicNumber != 0x13371234) {
        FatalError("Trying to interact with an invalid lock.");
    }
    
    // Attempt atomic release
    int64_t state = InterlockedDecrement64(&m_lockState);
    
    // Validate post-release state
    if ((state & READ_LOCKED_MASK) == READ_LOCKED_MASK) {
        assert(false && "(nCurrent & READ_LOCKED_MASK) != READ_LOCKED_MASK");
    }
    
    // Check for pending writers
    if ((state & READ_LOCKED_MASK) == 0 && (state & WRITE_LOCK_PENDING_MASK) != 0) {
        // Signal waiting writers
        SignalWriters(m_lockState);
    }
}

