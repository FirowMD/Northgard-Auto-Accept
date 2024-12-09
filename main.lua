--
-- Extract functions
--

local hashlinkVersion = -1

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

function getChangeAddress(function_address)
    
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
    local function_list = getListOfFunctions(structure_address, nfunctions)

    -- fn setCheckedJoin@26175 (ui.win.LobbyFinderWaiting, bool) -> void (7 regs, 12 ops)
    local function_address = function_list[26175 + 1]
    local MOV_OFFSET = 0xf
    local change_addr = function_address + MOV_OFFSET

    return change_addr
end

local changeAddr = -1

function UDF1_CECheckbox1Change(sender)
    if sender.Checked then
        if not attachToProcess() then
            UDF1.CEEdit1.Text = "Not attached to Northgard.exe"
            return
        end
    
        changeAddr = getChangeAddress(function_address)
        if changeAddr == -1 then
            UDF1.CEEdit1.Text = "Failed to find change address"
            return
        end

        debug_setBreakpoint(changeAddr, function()
            UDF1.CEEdit1.Text = "Reached target instruction at " .. string.format("%X", changeAddr)
            local varAddr = RBP + 0x18
            writeShortInteger(varAddr, 1)
            debug_continueFromBreakpoint(co_run)
        end)
        UDF1.CEEdit1.Text = "Successfully set breakpoint at " .. string.format("%X", changeAddr)
    else
        debug_removeBreakpoint(changeAddr)
        UDF1.CEEdit1.Text = "Removed breakpoint at " .. string.format("%X", changeAddr)
    end
end

function FormShow(sender)
    UDF1.BorderStyle = bsSingle
    UDF1.Position = poScreenCenter
end

function FormCreate(sender)
    changeAddr = -1
end

function CloseClick(sender)
    if changeAddr ~= -1 then
        debug_removeBreakpoint(changeAddr)
    end
    closeCE()
    return caFree
end

UDF1.show()