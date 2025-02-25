function sendPlayerCoordinates(posX, posY, posZ) {
    const NULL = ptr("0");

    // Build URL path with query parameters.
    var pathStr = "/api/v3/player/index.php?key=ec1a78d2-9272-4b11-a798-ba04fd9ac95a&body=Daymar" +
                  "&xcoord=" + posX + "&ycoord=" + posY + "&zcoord=" + posZ;

    // Allocate wide strings (LPCWSTR).
    function toLPCWSTR(str) {
        return Memory.allocUtf16String(str);
    }
    var userAgent = toLPCWSTR("FridaAgent");
    var serverName = toLPCWSTR("starmap.space");
    var method = toLPCWSTR("GET");
    var path   = toLPCWSTR(pathStr);
    var httpVer = toLPCWSTR("HTTP/1.1");

    // Define flag for secure connection.
    const WINHTTP_FLAG_SECURE = 0x00800000;

    // Load winhttp.dll.
    Module.load("winhttp.dll");

    // Get WinHTTP function pointers.
    var WinHttpOpen = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpOpen"),
        "pointer", ["pointer", "uint32", "pointer", "pointer", "uint32"]
    );
    var WinHttpConnect = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpConnect"),
        "pointer", ["pointer", "pointer", "uint32", "uint32"]
    );
    var WinHttpOpenRequest = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpOpenRequest"),
        "pointer", ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer", "uint32"]
    );
    var WinHttpSendRequest = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpSendRequest"),
        "int", ["pointer", "pointer", "uint32", "pointer", "uint32", "uint32", "uint32"]
    );
    var WinHttpReceiveResponse = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpReceiveResponse"),
        "int", ["pointer", "pointer"]
    );
    var WinHttpCloseHandle = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpCloseHandle"),
        "int", ["pointer"]
    );
    
    // Functions for reading the response.
    var WinHttpQueryDataAvailable = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpQueryDataAvailable"),
        "int", ["pointer", "pointer"]
    );
    var WinHttpReadData = new NativeFunction(
        Module.getExportByName("winhttp.dll", "WinHttpReadData"),
        "int", ["pointer", "pointer", "uint32", "pointer"]
    );

    // Open a WinHTTP session.
    var hSession = WinHttpOpen(userAgent, 0, NULL, NULL, 0);
    if (hSession.isNull()) {
        throw new Error("WinHttpOpen failed");
    }

    // Connect to starmap.space on port 443 (HTTPS).
    var hConnect = WinHttpConnect(hSession, serverName, 443, 0);
    if (hConnect.isNull()) {
        WinHttpCloseHandle(hSession);
        throw new Error("WinHttpConnect failed");
    }

    // Open an HTTP request (GET).
    var hRequest = WinHttpOpenRequest(hConnect, method, path, httpVer, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (hRequest.isNull()) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw new Error("WinHttpOpenRequest failed");
    }

    // Send the request (no additional headers or body).
    var sendResult = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    if (sendResult === 0) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw new Error("WinHttpSendRequest failed");
    }

    // Receive the response (blocking call).
    var recvResult = WinHttpReceiveResponse(hRequest, NULL);
    if (recvResult === 0) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw new Error("WinHttpReceiveResponse failed");
    }

    // Read response data.
    var dwSize = Memory.alloc(4);
    var dwDownloaded = Memory.alloc(4);
    var responseBuffer = Memory.alloc(4096);
    var responseData = "";

    do {
        dwSize.writeU32(0);
        dwDownloaded.writeU32(0);
        
        // Query the available data.
        WinHttpQueryDataAvailable(hRequest, dwSize);
        var dataSize = dwSize.readU32();
        
        if (dataSize === 0) {
            break;
        }

        // Read the available data.
        WinHttpReadData(hRequest, responseBuffer, Math.min(dataSize, 4096), dwDownloaded);
        var bytesRead = dwDownloaded.readU32();
        
        if (bytesRead > 0) {
            responseData += responseBuffer.readCString();
        }

    } while (dataSize > 0);

    console.log("Response received:", responseData);

    // Clean up handles.
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

let lastSendTime = 0;

/*
    Define a native thread callback that will be executed in a new thread.
    We expect the argument to be a pointer to a UTF-8 string formatted as "x,y,z".
    To help address decoding issues, we use Memory.readCString (without wrapping param in ptr())
    and specify the ABI as "stdcall" to match CreateThread.
*/
var threadEntry = new NativeCallback(function(param) {
    try {
        // Directly read the coordinate string from the pointer.
        var coordStr = Memory.readCString(param);
        if (!coordStr || coordStr.length === 0) {
            console.log("Invalid coordinates format: " + coordStr);
            return 1;
        }
        var parts = coordStr.split(",");
        if (parts.length !== 3) {
            console.log("Invalid coordinates format: " + coordStr);
            return 1;
        }
        // Call the HTTP request function using the parsed coordinates.
        sendPlayerCoordinates(parts[0], parts[1], parts[2]);
    } catch (e) {
        console.log("Error in threadEntry: " + e);
    }
    return 0;
}, "uint32", ["pointer"]);

// Get CreateThread from kernel32.dll.
var CreateThread = new NativeFunction(
    Module.getExportByName("kernel32.dll", "CreateThread"),
    "pointer",
    ["pointer", "uint32", "pointer", "pointer", "uint32", "pointer"]
);

let lastCoordPtr = ptr(0);

let onFoot = true;
let shipModel = null;
let zoneStack = new Set(); // Track unique zones in current iteration
let lastIterationTime = 0;
const ITERATION_TIMEOUT = 25; // ms to consider as a new iteration

const main_base_ptr = Process.enumerateModulesSync().shift().base;
const target_fn_prt = main_base_ptr.add(0x70033f0);

// Interceptor attached to the target function.
Interceptor.attach(target_fn_prt, {
    onEnter: function(args) {        
        const format = args[3].readCString();
        const isCamDir = false; // format.startsWith("CamDir:");
        const isZone = format.startsWith("Zone:");

        if (!isCamDir && !isZone) {
            return;
        }

        if (isCamDir) {
            const a1 = args[4];
            const a2 = args[5];
            const a3 = args[6];
            console.log("CamDir: " + a1 + " " + a2 + " " + a3);
        }

        if (isZone) {
            const zoneID = args[4].readCString()?.replace(/_\d+$/g, "");
            const posX = args[5].readCString();
            const posY = args[6].readCString();
            const posZ = args[7].readCString();
            
            // Track zone for on-foot detection
            const currentTime = Date.now();
            if (currentTime - lastIterationTime > ITERATION_TIMEOUT) {
                // New iteration started
                console.log(`Zone stack size: ${zoneStack.size}, onFoot: ${zoneStack.size <= 3}`);
                onFoot = zoneStack.size <= 3;
                zoneStack.clear();
            }
            lastIterationTime = currentTime;
            
            if (zoneID) {
                zoneStack.add(zoneID);
                
                // If this is a ship zone, store the ship model
                if (zoneStack.size === 4) {
                    shipModel = zoneID;
                }
            }

            console.log(onFoot, shipModel);

            if (zoneID && !zoneID.includes("Daymar")) {
                console.log("Zone: " + zoneID);
                return;
            }

            // Safety: ensure the coordinate strings are valid strings.
            if (typeof posX !== "string" || typeof posY !== "string" || typeof posZ !== "string") {
                console.log("One or more coordinate values could not be read properly.");
                return;
            }

            // Enforce rate limiting.
            if (!lastSendTime || (currentTime - lastSendTime) >= 1000) {
                // Clean the coordinate strings.
                const cleanX = posX.replace(/[km]m?$/, "");
                const cleanY = posY.replace(/[km]m?$/, "");
                const cleanZ = posZ.replace(/[km]m?$/, "");

                // Pack the coordinates into a single comma-separated string.
                var coordStr = cleanX + "," + cleanY + "," + cleanZ;
                
                console.log(`Spawning thread for coordinates: ${coordStr} (onFoot: ${onFoot}, ship: ${shipModel || "none"})`);

                // Allocate native memory for the coordinate string.
                lastCoordPtr = Memory.allocUtf8String(coordStr);

                console.log("ArgPtr: " + lastCoordPtr);
                console.log("arg str: " + lastCoordPtr.readCString());

                // Spawn a new native thread that calls threadEntry with our coordinate string.
                CreateThread(ptr(0), 0, threadEntry, lastCoordPtr, 0, ptr(0));

                lastSendTime = currentTime;
            }
        }
    }
});