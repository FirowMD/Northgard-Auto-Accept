--
-- Extract functions
--

local hashlinkVersion = -1
local memoContent = {}
local memoPlayers = {}
local function_list = {}
local queueMembers = {}
local changeAddr = -1
local changeAddr1 = -1
local changeAddr2 = -1
local changeAddr3 = -1

function convertAddressToScanData(address)
    local addr = tonumber(address, 16)
    if not addr then
        return nil
    end

    local bytes = qwordToByteTable(addr)
    
    local pattern = {}
    for i=1, #bytes do
        pattern[i] = string.format("%02X", bytes[i])
    end
    
    return table.concat(pattern, " ")
end

local function isUtf16Match(bytes, startIndex, searchString)
    for i = 1, #searchString do
        local char = string.byte(searchString:sub(i,i))
        local byteIndex = startIndex + (i-1)*2
        
        if bytes[byteIndex] ~= char or bytes[byteIndex + 1] ~= 0 then
            return false
        end
    end
    return true
end

local function searchUtf16StringInRegion(bytes, searchString, baseAddress)
    local searchLength = #searchString * 2
    
    for i = 1, #bytes - searchLength do
        if isUtf16Match(bytes, i, searchString) then
            return string.format("%X", baseAddress + i - 1)
        end
    end
    
    return nil
end

function findHlbootdatAddress()
    local EXPECTED_STRING = "hlboot.dat"
    local IMAGE_TYPE = 0x1000000

    local regions = enumMemoryRegions()
    
    for _, region in ipairs(regions) do
        if region.Type == IMAGE_TYPE then
            local bytes = readBytes(region.BaseAddress, region.RegionSize, true)
            
            if bytes then
                local address = searchUtf16StringInRegion(bytes, EXPECTED_STRING, region.BaseAddress)
                if address then
                    return address
                end
            end
        end
    end

    return nil, "Could not find 'hlboot.dat' string in memory!"
end

function setup_hashlink_version(structure_address)
    local struct_addr = tonumber(structure_address, 16)
    -- addr: hl_code *code;
    local addr = readQword(struct_addr + 0x8)
    local possible_values = {3, 4, 5}
    for _, value in ipairs(possible_values) do
        current_value = readInteger(addr)
        if current_value == value then
            hashlinkVersion = value
            return true
        end
    end

    return false
end

function getHashlinkNfunctions(structure_address)
    --[[
    hl_code* code structure:
    	int version;    +0
        int nints;      +4
        int nfloats;    +8
        int nstrings;   +12
        [int nbytes;    +16] // version >= 4
        int ntypes;     +16 [+20]
        int nglobals;   +20 [+24]
        int nnatives;   +24 [+28]
        int nfunctions; +28 [+32]
    ]]--

    local NFUNCTIONS_OFFSET = 28
    if hashlinkVersion >= 4 then
        NFUNCTIONS_OFFSET = 32
    end

    local struct_addr = tonumber(structure_address, 16)
    -- addr: hl_code *code;
    local addr = readQword(struct_addr + 0x8)
    local nfunctions = readInteger(addr + NFUNCTIONS_OFFSET)

    return nfunctions
end


function getStructureAddress(hlboot_dat_address)
    local scandata = convertAddressToScanData(hlboot_dat_address)
    if not scandata then
        return nil
    end

    local results = AOBScan(scandata, "+W")
    if not results or results.Count == 0 then
        if results then results.destroy() end
        return nil
    end

    local structureAddress = nil
    for i = 0, results.Count - 1 do
        local addr = results[i]
        if setup_hashlink_version(addr) then
            structureAddress = addr
            break
        end
    end

    results.destroy()
    return structureAddress
end

function getListOfFunctions(structure_address, nfunctions)
    local result = {}
    local struct_addr = tonumber(structure_address, 16)
    local hl_module_pointer = readQword(struct_addr + 0x10)
    local functions_pointer = readQword(hl_module_pointer + 0x20)
    
    local bytes = readBytes(functions_pointer, nfunctions * 8, true)
    if not bytes then
        return result
    end
    
    for i = 1, #bytes, 8 do
        local function_address = byteTableToQword({
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7] 
        })

        table.insert(result, function_address)
    end
    
    return result
end


--
-- Auto accept
--

local function attachToProcess()
    UDF1.CEEdit1.Text = "Try to attach to Northgard.exe"
    
    local retries = 0
    local maxRetries = 10
    
    while getProcessIDFromProcessName("Northgard.exe") == 0 do
        sleep(100)
        retries = retries + 1
        if retries >= maxRetries then
            showMessage("Could not find Northgard.exe after " .. maxRetries .. " attempts")
            return false
        end
    end
    
    local processID = getProcessIDFromProcessName("Northgard.exe")
    if processID ~= 0 then
        if openProcess(processID) then
            UDF1.CEEdit1.Text = "Attached to Northgard.exe (PID: " .. processID .. ")"
            return true
        else
            showMessage("Failed to open process Northgard.exe")
            return false
        end
    end

    return false
end

function UpdateFunctionList()
    local hlboot_address, error = findHlbootdatAddress()
    if not hlboot_address then
        showMessage(error)
        return
    end

    local structure_address = getStructureAddress(hlboot_address)
    if not structure_address then
        showMessage("Could not find pointer to 'hlboot.dat' address!")
        return
    end

    local nfunctions = getHashlinkNfunctions(structure_address)
    function_list = getListOfFunctions(structure_address, nfunctions)

    UDF1.CEEdit1.Text = "Function list updated"
end

-- fn setCheckedJoin@26465
function getChangeAddress(function_address)
    local hex_pattern = "488B??????????4889????4885??75??4883????68????????48B8????????????????4883????FF??4889??????4C??????4C??????498B??48B9????????????????48B8????????????????4883????FF??4889??????4883????4889????4885??75??48B8????????????????4883????FF??4889??????4833"
    local change_addr = AOBScanUnique(hex_pattern)
    if change_addr == nil then
        showMessage("Failed to find change address: setCheckedJoin")
        return -1
    end

    return change_addr
end

function UDF1_CECheckbox1Change(sender)
    if sender.Checked then
        debug_setBreakpoint(changeAddr, function()
            UDF1.CEEdit1.Text = "Reached target instruction at " .. string.format("%X", changeAddr)
            local varAddr = RBP + 0x18
            writeShortInteger(varAddr, 1)
            debug_continueFromBreakpoint(co_run)
        end)
        UDF1.CEEdit1.Text = "Auto accept enabled"
    else
        debug_removeBreakpoint(changeAddr)
        UDF1.CEEdit1.Text = "Auto accept disabled"
    end
end

function FormShow(sender)
    UDF1.BorderStyle = bsSingle
    UDF1.Position = poScreenCenter
end

function CloseClick(sender)
    if changeAddr ~= -1 then
        debug_removeBreakpoint(changeAddr)
    end
    if changeAddr1 ~= -1 then
        debug_removeBreakpoint(changeAddr1)
    end
    if changeAddr2 ~= -1 then
        debug_removeBreakpoint(changeAddr2)
    end
    if changeAddr3 ~= -1 then
        debug_removeBreakpoint(changeAddr3)
    end
    closeCE()
    return caFree
end

-- fn logLobbyInfo@29844
function getLogAddress1()
    local OFFSET = 2035
    local hex_pattern = "55488B??4881??????????4889????4885??75??4883????68????????48B8????????????????4883????FF??4889??????488B????4889????488B"
    local function_address = AOBScanUnique(hex_pattern)
    if function_address == nil then
        showMessage("Failed to find change address: logLobbyInfo")
        return -1
    end

    return function_address + OFFSET
end

-- fn logUserJoined@29845
function getLogAddress2()
    local hex_pattern = "4889??????4883????4889????48B9????????????????488B??4889????488B??4883????E8????????4889??????4883????4889????488B????4885??0F85????????49B8????????????????4D????4C??????E9????????4C??????4C??????488B????488B????4883????E8????????4889??????4883????4889????4D????4C??????488B??498B??4883????E8????????4889??????4883????488B????4883????5D48C39090909090909090909055488B??4883????4889"
    local function_address = AOBScanUnique(hex_pattern)
    if function_address == nil then
        showMessage("Failed to find change address: logUserJoined")
        return -1
    end

    return function_address
end

-- fn logUserLeft@29846
function getLogAddress3()
    local hex_pattern = "4889??????4883????4889????48B9????????????????488B??4889????488B??4883????E8????????4889??????4883????4889????488B????4885??0F85????????49B8????????????????4D????4C??????E9????????4C??????4C??????488B????488B????4883????E8????????4889??????4883????4889????4D????4C??????488B??498B??4883????E8????????4889??????4883????488B????4883????5D48C39090909090909090909055488B??4883????88"
    local function_address = AOBScanUnique(hex_pattern)
    if function_address == nil then
        showMessage("Failed to find change address: logUserLeft")
        return -1
    end

    return function_address
end

function parsePlayerInfo(str)
    -- Extract player name and ID from formats like:
    -- "PlayerName(SomeID)" or "PlayerName(SomeID)(TeamX)"
    local closePos = str:match(".*()%)")
    if not closePos then return nil end

    for i = closePos - 1, 1, -1 do
        if str:sub(i, i) == "(" then
            local name = str:sub(1, i - 1)
            local id = str:sub(i + 1, closePos - 1)
            return name, id
        end
    end

    return nil
end

function getLogData()
    local LOG_OFFSET = 8
    local logAddr = readPointer(RAX + LOG_OFFSET)
    local logData = readString(logAddr, 2000, true)
    logData = logData:gsub(" ", "")
    logData = logData:gsub("\t", "")
    return logData
end

function updateQueueDisplay()
    UDF1.CEMemo1.Lines.Clear()
    for player, _ in pairs(queueMembers) do
        UDF1.CEMemo1.Lines.Add(player)
    end
end

function UDF1_CECheckbox2Change(sender)
    if sender.Checked then
        queueMembers = {} -- Reset queue members list

        debug_setBreakpoint(changeAddr1, function()
            local isMembers = false
            local logData = getLogData()
            -- Clear previous queue state when new lobby info arrives
            queueMembers = {}
            -- Process each line
            for line in logData:gmatch("[^\r\n]+") do
                if line:find("Slots:") then
                    isMembers = false
                end
                
                if isMembers then
                    local name, id = parsePlayerInfo(line)
                    if name and id then
                        queueMembers[name] = id
                    end
                end

                if line:find("Members:") then
                    isMembers = true
                end
            end
            updateQueueDisplay()
            debug_continueFromBreakpoint(co_run)
        end)
        
        debug_setBreakpoint(changeAddr2, function() 
            local logData = getLogData()
            local name, id = parsePlayerInfo(logData)
            if name and id then
                queueMembers[name] = id
                updateQueueDisplay()
            end
            debug_continueFromBreakpoint(co_run)
        end)

        debug_setBreakpoint(changeAddr3, function() 
            local logData = getLogData()
            local name, id = parsePlayerInfo(logData)
            if name then
                queueMembers[name] = id
                updateQueueDisplay()
            end
            debug_continueFromBreakpoint(co_run)
        end)
        
        UDF1.CEEdit1.Text = "Tracking queue enabled"
    else
        debug_removeBreakpoint(changeAddr1)
        debug_removeBreakpoint(changeAddr2)
        debug_removeBreakpoint(changeAddr3)
        UDF1.CEEdit1.Text = "Tracking queue disabled"
    end
end

function UpdateAddresses()
    changeAddr = getChangeAddress(function_address)
    if changeAddr == -1 then
        UDF1.CEEdit1.Text = "Failed to find `setCheckedJoin` address"
        return
    end

    changeAddr1 = getLogAddress1()
    if changeAddr1 == -1 then
        UDF1.CEEdit1.Text = "Failed to find `logLobbyInfo` address"
        return
    end

    changeAddr2 = getLogAddress2()
    if changeAddr2 == -1 then
        UDF1.CEEdit1.Text = "Failed to find `logUserJoined` address"
        return
    end

    changeAddr3 = getLogAddress3()
    if changeAddr3 == -1 then
        UDF1.CEEdit1.Text = "Failed to find `logUserLeft` address"
        return
    end

    UDF1.CEEdit1.Text = "Addresses updated"
end

function ClearEverything()
    UDF1.CEMemo1.Lines.Clear()
    UDF1.CEEdit1.Text = ""
    UDF1.CECheckbox1.Checked = false
    UDF1.CECheckbox2.Checked = false
end

function UDF1_CECustomButton1Click(sender)
    ClearEverything()

    if not attachToProcess() then
        UDF1.CEEdit1.Text = "Not attached to Northgard.exe"
        return
    end

    UpdateAddresses()
    UDF1.CEEdit1.Text = "Data updated"
end


UDF1.show()
ClearEverything()
