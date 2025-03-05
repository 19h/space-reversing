// Forward declarations
class CZoneSystem;
class CZone;
class SZoneObject;
class CigRWLock;
struct SThreadInfoBlock;
struct Vec3;

// Main zone handle content structure
struct SZoneHandleContent {
    // Thread synchronization
    void* m_pOwner;              // Owner thread identifier
    const char* m_pReaderName;   // Reader identification string
    int m_nReaderRefCount;       // Reader reference counter
    volatile int m_nReaderCount; // Concurrent reader counter
    
    void* m_pTransformOwner;     // Transform access owner
    const char* m_pTransformName;// Transform access name
    int m_nTransformRefCount;    // Transform reference counter
    volatile int m_nTransformCount; // Concurrent transform access counter
    
    // Content data
    uint64_t m_data[6];          // Zone data
    uint64_t m_matrix[8];        // Transformation matrix
    
    // Type and identification
    uint16_t m_nZoneID;          // Zone identifier
    uint16_t m_nParentZoneID;    // Parent zone identifier
    uint16_t m_typeIndex;        // Type index (0-4)
    
    // Zone state
    bool m_bWorldSpacePositionDirty; // Position needs update flag
    uint32_t m_nUpdateCounter;   // Update counter for dirty tracking
};

// Position vector
struct Vec3 {
    double x, y, z;
};

// Complete transform with position and orientation
struct SZoneTransform {
    Vec3 position;      // Position vector
    Vec3 orientation;   // Orientation vector
    Vec3 scale;         // Scale vector (if applicable)
};

/**
 * Retrieves the world space position for a zone object
 * 
 * @param zoneSystem Pointer to zone system instance
 * @param outPosition Buffer to receive position data
 * @param zoneHandle Handle to the zone object
 * @param flags Operation flags:
 *        - 0: Use global state lock
 *        - 2: Use lightweight position access
 *        - 3: Direct access (no position data if unavailable)
 * @return Filled position buffer
 */
Vec3* CZoneSystem::GetPosition(CZoneSystem* zoneSystem, Vec3* outPosition, uint32_t* zoneHandle, int flags)
{
    PROFILE_FUNCTION("CZoneSystem::GetPosition");
    
    // Invalid zone handle check (0xFFFFFF means invalid zone)
    if (((*zoneHandle) & 0xFFFFFF) == 0xFFFFFF) {
        *outPosition = Vec3(0, 0, 0);
        return outPosition;
    }
    
    // Get zone handle content from handle
    SZoneHandleContent* zoneContent = ResolveZoneHandle(zoneSystem, zoneHandle);
    
    // Based on access flags
    if (flags == 0) {
        // Full thread-safe access with system lock
        bool isInFiber = IsExecutingInFiber();
        
        // Acquire global state lock if not in fiber
        if (!isInFiber) {
            AcquireGlobalStateLock(zoneSystem);
        }
        
        // Acquire read lock for the zone content
        AcquireReaderLock(zoneContent);
        
        // Acquire transform lock for the zone content
        AcquireTransformLock(zoneContent);
        
        // Get zone instance for the content
        CZone* zone = GetZoneFromID(zoneSystem, zoneContent->m_nZoneID);
        
        // Get transform data
        Vec3* transformData = GetZoneTransformData(zoneSystem, zoneContent);
        
        // Copy transform to output buffer
        CopyTransformToOutput(zone, outPosition, transformData);
        
        // Release transform lock
        ReleaseTransformLock(zoneContent);
        
        // Release content lock
        ReleaseReaderLock(zoneContent);
        
        // Release global state lock if not in fiber
        if (!isInFiber) {
            ReleaseGlobalStateLock(zoneSystem);
        }
    } 
    else if (flags == 2) {
        // Lightweight access (transform-only lock)
        AcquireTransformLock(zoneContent);
        
        // Get transform data directly
        Vec3* transformData = GetZoneTransformData(zoneSystem, zoneContent);
        
        // Copy to output
        CopyTransformToOutput(nullptr, outPosition, transformData);
        
        // Release transform lock
        ReleaseTransformLock(zoneContent);
    }
    else if (flags == 3) {
        // Empty position on direct access when no zone available
        *outPosition = Vec3(0, 0, 0);
    }
    else {
        // Invalid flags
        assert(false && "Invalid flag in GetPosition");
    }
    
    return outPosition;
}

/**
 * Refreshes world space position for a zone
 * 
 * @param zone Pointer to zone instance
 * @param updateCounter Current update counter
 * @return True if position was updated
 */
bool CZone::RefreshWorldSpacePosition(CZone* zone, uint32_t updateCounter)
{
    // Skip if already up-to-date
    if (zone->m_nUpdateCounter == CZoneSystem::GetGlobalUpdateCounter())
        return true;
        
    // Lock transformation for thread safety
    LockTransformation(zone);
    
    // Check for parent zone
    if (zone->m_pParentZone) {
        // Get parent zone transform
        SZoneTransform parentTransform;
        GetTransform(zone->m_pParentZone, &parentTransform, updateCounter);
        
        // Calculate combined transform
        CalculateCombinedTransform(zone, &parentTransform);
    }
    
    // Update transformation counter
    zone->m_nUpdateCounter = updateCounter;
    
    // Unlock transformation
    UnlockTransformation(zone);
    
    return true;
}

/**
 * Calculates transformation matrices between zone and parent
 * 
 * @param zone The zone to transform
 * @param parentTransform Parent zone transform
 */
void CalculateCombinedTransform(CZone* zone, SZoneTransform* parentTransform)
{
    // Local variables for matrix calculation
    double m11, m12, m13, m21, m22, m23, m31, m32, m33;
    double v1, v2, v3, v4, v5, v6, v7, v8, v9;
    
    // Extract local transform values
    double lx = zone->m_localTransform.position.x;
    double ly = zone->m_localTransform.position.y;
    double lz = zone->m_localTransform.position.z;
    
    double ox = zone->m_localTransform.orientation.x;
    double oy = zone->m_localTransform.orientation.y;
    double oz = zone->m_localTransform.orientation.z;
    
    // Extract parent transform values
    double px = parentTransform->position.x;
    double py = parentTransform->position.y;
    double pz = parentTransform->position.z;
    
    double pox = parentTransform->orientation.x;
    double poy = parentTransform->orientation.y;
    double poz = parentTransform->orientation.z;
    
    // Calculate rotation matrix components
    m11 = poz * ly - poy * lz;
    m12 = pox * lz - poz * lx;
    m13 = poy * lx - pox * ly;
    
    // Combine local and parent transformations
    zone->m_worldTransform.position.x = px + m11;
    zone->m_worldTransform.position.y = py + m12;
    zone->m_worldTransform.position.z = pz + m13;
    
    // Calculate orientation components
    zone->m_worldTransform.orientation.x = zone->m_localTransform.orientation.x;
    zone->m_worldTransform.orientation.y = zone->m_localTransform.orientation.y;
    zone->m_worldTransform.orientation.z = zone->m_localTransform.orientation.z;
}

/**
 * Thread-safe reader lock acquisition
 * 
 * @param lock The lock to acquire
 * @param callerName Name of the caller for debugging
 * @param lockName Name of the lock for debugging
 */
void AcquireReaderLock(CigRWLock* lock, const char* callerName, const char* lockName)
{
    // Try to acquire lock without waiting
    if ((lock->m_nState & 0x200000) == 0)
        return;
    
    uint64_t state = lock->m_nState;
    while (true) {
        // Check if lock has writer blocker flag (0x200000)
        if ((state & 0x200000) != 0) {
            // Try to set waiting flag
            if ((state & 0x100000) == 0) {
                int newState = state | 0x100000;
                int64_t oldState = InterlockedCompareExchange64(&lock->m_nState, newState, state);
                if (oldState == state) {
                    // Successfully marked as waiting, now wait
                    WaitForReaderLock(lock, "Wait For RLock", lockName, callerName);
                    state = lock->m_nState;
                } else {
                    state = oldState;
                }
                continue;
            }
        }
        break;
    }
}

/**
 * Thread-safe reader lock release
 * 
 * @param lock The lock to release
 */
void ReleaseReaderLock(CigRWLock* lock)
{
    // Validate lock object
    if (lock->m_nMagic != LOCK_MAGIC_NUMBER)
        FatalError("Trying to interact with an invalid lock.");
    
    // Decrement reader count
    int64_t state = InterlockedDecrement64(&lock->m_nState);
    
    // Check if we were the last reader
    if ((state & 0x3FF) == 0) {
        // If there are waiters, notify them
        if ((state & 0xFFFF0000FFC00000ULL) != 0) {
            NotifyWaiters(lock, state);
        }
    }
}

/**
 * Handles assertion failures
 * 
 * @param expression The expression that failed
 * @param filename Source file where assertion failed
 * @param line Line number of assertion
 * @param message Additional failure message
 */
void HandleAssertFailure(const char* expression, const char* filename, int line, const char* message)
{
    // Get thread information
    SThreadInfoBlock* threadInfo = GetThreadInfoBlock();
    
    // Lock assertion handling
    AcquireAssertionLock();
    
    // Format assertion message
    char buffer[1024];
    sprintf(buffer, "Assertion failed: %s\nFile: %s\nLine: %d\nMessage: %s",
            expression, filename, line, message);
    
    // Log assertion failure
    LogAssertionFailure(buffer);
    
    // Check if debugger is present
    if (IsDebuggerPresent()) {
        // Break into debugger
        __debugbreak();
    } else {
        // Log to console or file
        fprintf(stderr, "%s\n", buffer);
        
        // In release builds, try to continue
        #ifndef _DEBUG
        if (ShouldIgnoreAssertions()) {
            ReleaseAssertionLock();
            return;
        }
        #endif
    }
    
    // Show assertion dialog when appropriate
    if (CanShowAssertDialog()) {
        if (ShowAssertDialog(expression, filename, line, message) == ASSERT_ACTION_BREAK) {
            __debugbreak();
        }
    }
    
    // Release assertion lock
    ReleaseAssertionLock();
}

/**
 * Formats a timestamp into ISO 8601 format
 * 
 * @param buffer Output buffer
 * @param bufferSize Size of the buffer
 * @param timestamp Timestamp in milliseconds
 * @return Number of characters written or -1 on error
 */
int64_t FormatTimestamp(char* buffer, size_t bufferSize, uint64_t timestamp)
{
    // Validate buffer size
    if (bufferSize < 32)
        return -1;
    
    // Split timestamp into seconds and milliseconds
    uint64_t seconds = timestamp / 1000;
    uint32_t milliseconds = timestamp - (seconds * 1000);
    
    // Convert to GMT time
    time_t timeSeconds = seconds;
    struct tm timeInfo;
    gmtime_s(&timeInfo, &timeSeconds);
    
    // Format main time portion
    strftime(buffer, bufferSize, "%Y-%m-%dT%H:%M:%S", &timeInfo);
    
    // Append milliseconds
    return strlen(buffer) + swprintf((wchar_t*)(buffer + 19), bufferSize - 19, L".%03dZ", milliseconds);
}

/**
 * Converts an unsigned integer to string
 * 
 * @param str Output string buffer
 * @param size Buffer size
 * @param pos Starting position
 * @param value Value to convert
 * @return Number of characters written or -1 on error
 */
int64_t UIntToString(char* str, int size, int64_t pos, uint64_t value)
{
    int count = 0;
    int64_t startPos = pos;
    
    if (pos >= size)
        return -1;
    
    // Convert digits in reverse order
    do {
        if (count >= size - pos || pos < 0)
            return -1;
            
        count++;
        str[pos++] = (value % 10) + '0';
        value /= 10;
    } while (value > 0);
    
    // Reverse the digits
    if (count > 0) {
        char* end = str + pos - 1;
        char* start = str + startPos;
        
        while (start < end) {
            char temp = *start;
            *start++ = *end;
            *end-- = temp;
        }
    }
    
    return count;
}

