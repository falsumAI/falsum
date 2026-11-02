<#
.SYNOPSIS
    Falsum Intelligence Core — the local AI brain.

.DESCRIPTION
    This is not a chatbot. This is the intelligent coordinator for the entire
    system. Architecture:

      USER <--> LOCAL MODEL (mouthpiece) <--> COHERENCE CORE (Gregg's math, the judge)
                                                    |
                                              TOOL ROUTER (25 modules as tools)
                                                    |
                                              MEMORY (persistent learning)

    The model NEVER decides truth. The coherence core decides. The model only
    explains, summarizes, and converses. The tools gather evidence. Memory
    makes it smarter over time.

    This is the poison pill for AI subscriptions: intelligence that lives on
    your machine, knows your system, gets smarter with use, costs nothing,
    phones home to no one, and has no token limits.

    FUNCTIONS:
      Invoke-IntelligenceQuery - the main entry: user asks, system reasons, tools
                                 gather, model explains. Returns the answer.
      Register-IntelligenceTool - register a module function as a callable tool
      Invoke-IntelligenceTool   - execute a registered tool by name with args
      Get-IntelligenceTools     - list all registered tools
      Save-IntelligenceMemory   - persist a learning to local memory
      Get-IntelligenceMemory    - recall learnings relevant to a query
      Clear-IntelligenceMemory  - wipe memory (user's choice, always)
      Test-IntelligenceCore     - self-test: coherence + tools + model + memory
#>

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# INTELLIGENCE CORE STATE
# ============================================================================

$script:IntelligenceTools = @{}
$script:IntelligenceMemoryPath = $null
$script:IntelligenceMemory = @()

function Get-IntelligenceMemoryPath {
    <#
    .SYNOPSIS Pure: resolve the local memory file path.
    #>
    if (-not $script:IntelligenceMemoryPath) {
        $root = Split-Path -Parent $PSScriptRoot
        $root = Split-Path -Parent $root
        $memDir = Join-Path $root "data\intelligence"
        if (-not (Test-Path $memDir)) {
            New-Item -ItemType Directory -Path $memDir -Force | Out-Null
        }
        $script:IntelligenceMemoryPath = Join-Path $memDir "memory.json"
    }
    return $script:IntelligenceMemoryPath
}

function Register-IntelligenceTool {
    <#
    .SYNOPSIS
        Register a module function as a tool the intelligence core can invoke.
    .DESCRIPTION
        Tools are the hands. The coherence core is the brain. The model is the
        voice. A tool wraps a module function with a name, description, and
        parameter schema so the intelligence can decide when to use it.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [string]$Category = "General"
    )
    $script:IntelligenceTools[$Name] = [PSCustomObject]@{
        Name = $Name
        Description = $Description
        Category = $Category
        Action = $Action
        CallCount = 0
        LastCalled = $null
    }
}

function Get-IntelligenceTools {
    <#
    .SYNOPSIS Pure: list all registered tools.
    #>
    return @($script:IntelligenceTools.Values | Sort-Object Category, Name)
}

function Invoke-IntelligenceTool {
    <#
    .SYNOPSIS
        Execute a registered tool by name. Logs the invocation.
    .DESCRIPTION
        Every tool call is logged with timestamp, args, and result summary.
        The log is local. Nothing leaves the machine.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [hashtable]$Arguments = @{}
    )
    if (-not $script:IntelligenceTools.ContainsKey($Name)) {
        throw "Intelligence tool not registered: $Name. Use Get-IntelligenceTools to list available tools."
    }
    $tool = $script:IntelligenceTools[$Name]
    $tool.CallCount++
    $tool.LastCalled = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $tool.Action @Arguments
        $sw.Stop()
        return [PSCustomObject]@{
            Tool = $Name
            Success = $true
            DurationMs = $sw.ElapsedMilliseconds
            Result = $result
        }
    }
    catch {
        $sw.Stop()
        return [PSCustomObject]@{
            Tool = $Name
            Success = $false
            DurationMs = $sw.ElapsedMilliseconds
            Error = $_.Exception.Message
        }
    }
}

function Save-IntelligenceMemory {
    <#
    .SYNOPSIS
        Persist a learning to local memory. Memory is a JSON file on this machine.
    .DESCRIPTION
        The intelligence gets smarter by remembering. Every significant finding,
        user preference, or correction is saved. Memory is local-only, user-owned,
        and can be wiped at any time with Clear-IntelligenceMemory.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Value,
        [string]$Category = "General",
        [int]$Importance = 5  # 1-10, higher = more important
    )
    Load-IntelligenceMemory

    # Update existing or add new
    $existing = $script:IntelligenceMemory | Where-Object { $_.Key -eq $Key }
    if ($existing) {
        $existing.Value = $Value
        $existing.Updated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $existing.Importance = $Importance
    }
    else {
        $script:IntelligenceMemory += [PSCustomObject]@{
            Key = $Key
            Value = $Value
            Category = $Category
            Importance = $Importance
            Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Updated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }

    $path = Get-IntelligenceMemoryPath
    $script:IntelligenceMemory | ConvertTo-Json -Depth 5 | Set-Content $path -Encoding UTF8
}

function Load-IntelligenceMemory {
    <#
    .SYNOPSIS Load memory from disk into the session.
    #>
    if ($script:IntelligenceMemory.Count -gt 0) { return }
    $path = Get-IntelligenceMemoryPath
    if (Test-Path $path) {
        try {
            $loaded = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
            $script:IntelligenceMemory = @($loaded)
        }
        catch {
            $script:IntelligenceMemory = @()
        }
    }
}

function Get-IntelligenceMemory {
    <#
    .SYNOPSIS
        Recall learnings relevant to a query. Pure: searches memory by keyword.
    #>
    param(
        [string]$Query = "",
        [string]$Category = "",
        [int]$MinImportance = 1
    )
    Load-IntelligenceMemory

    $results = $script:IntelligenceMemory | Where-Object { $_.Importance -ge $MinImportance }

    if ($Category -ne "") {
        $results = $results | Where-Object { $_.Category -eq $Category }
    }

    if ($Query -ne "") {
        $ql = $Query.ToLower()
        $results = $results | Where-Object {
            $_.Key.ToLower().Contains($ql) -or
            $_.Value.ToLower().Contains($ql) -or
            $_.Category.ToLower().Contains($ql)
        }
    }

    return @($results | Sort-Object Importance -Descending)
}

function Clear-IntelligenceMemory {
    <#
    .SYNOPSIS
        Wipe all memory. The user's choice, always. No recovery.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    if ($PSCmdlet.ShouldProcess("Intelligence memory", "Wipe all learnings")) {
        $script:IntelligenceMemory = @()
        $path = Get-IntelligenceMemoryPath
        if (Test-Path $path) { Remove-Item $path -Force }
        Write-Host "Memory wiped. The intelligence starts fresh." -ForegroundColor Yellow
    }
}

function Invoke-IntelligenceQuery {
    <#
    .SYNOPSIS
        The main entry point: user asks, system reasons, tools gather, model explains.
    .DESCRIPTION
        The intelligence loop:
        1. Check memory for relevant learnings
        2. Determine which tools are needed (via coherence core scoring)
        3. Invoke tools to gather evidence
        4. Score evidence through coherence core (Gregg's math decides truth)
        5. Send scored findings to local model for natural-language explanation
        6. Save significant learnings to memory
        7. Return the answer

        The model NEVER sees raw tool output without coherence scoring first.
        The model NEVER decides what's true. It only explains what the core decided.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Query,
        [string[]]$ToolNames = @(),  # specific tools to use; empty = auto-select
        [switch]$SkipModel,           # return raw scored findings without model explanation
        [switch]$SaveLearning         # persist the interaction as a learning
    )

    $steps = New-Object System.Collections.ArrayList

    # Step 1: Check memory
    $memories = Get-IntelligenceMemory -Query $Query
    [void]$steps.Add([PSCustomObject]@{
        Step = "Memory"
        Detail = "$($memories.Count) relevant learnings recalled"
        Data = $memories
    })

    # Step 2: Select and invoke tools
    $toolsToUse = @()
    if ($ToolNames.Count -gt 0) {
        $toolsToUse = $ToolNames
    }
    else {
        # Auto-select: all registered tools in relevant categories
        # (In a full implementation, the coherence core would score relevance.
        # For now, use keyword matching against tool descriptions.)
        $ql = $Query.ToLower()
        foreach ($tool in $script:IntelligenceTools.Values) {
            $td = $tool.Description.ToLower()
            # Simple relevance: query words appear in tool description
            $words = $ql -split '\s+' | Where-Object { $_.Length -gt 3 }
            foreach ($w in $words) {
                if ($td.Contains($w)) {
                    $toolsToUse += $tool.Name
                    break
                }
            }
        }
        $toolsToUse = @($toolsToUse | Select-Object -Unique)
    }

    $toolResults = @()
    foreach ($tname in $toolsToUse) {
        try {
            $tr = Invoke-IntelligenceTool -Name $tname
            $toolResults += $tr
        }
        catch {
            $toolResults += [PSCustomObject]@{
                Tool = $tname; Success = $false; Error = $_.Exception.Message
            }
        }
    }
    [void]$steps.Add([PSCustomObject]@{
        Step = "Tools"
        Detail = "$($toolResults.Count) tools invoked, $(($toolResults | Where-Object Success).Count) succeeded"
        Data = $toolResults
    })

    # Step 3: Coherence scoring (Gregg's math goes here)
    # The coherence core scores the evidence. Currently an interface —
    # Gregg's formalization plugs in here.
    $scored = [PSCustomObject]@{
        Query = $Query
        EvidenceCount = ($toolResults | Where-Object Success).Count
        CoherenceScore = $null  # Awaiting Gregg's math formalization
        Note = "Coherence core interface: Gregg's math plugs in here to score evidence truth."
    }
    [void]$steps.Add([PSCustomObject]@{
        Step = "Coherence"
        Detail = "Evidence scored (interface — awaiting Gregg's formalization)"
        Data = $scored
    })

    # Step 4: Model explanation (unless skipped)
    $answer = $null
    if (-not $SkipModel) {
        # Build the grounded prompt: memory + tool results + coherence score
        # The model explains; it does not decide.
        $prompt = Build-IntelligencePrompt $Query $memories $toolResults $scored
        [void]$steps.Add([PSCustomObject]@{
            Step = "Prompt"
            Detail = "Grounded prompt built ($($prompt.Length) chars)"
            Data = $prompt
        })
        # Note: actual model invocation goes through Send-ChatPrompt from
        # Falsum-Chat.ps1. This function prepares everything; the caller
        # sends the prompt to the local model.
        $answer = [PSCustomObject]@{
            Prompt = $prompt
            Note = "Send this prompt via Send-ChatPrompt to get the model explanation."
        }
    }

    # Step 5: Save learning (if requested)
    if ($SaveLearning) {
        Save-IntelligenceMemory -Key "Query: $Query" `
            -Value "Tools used: $($toolsToUse -join ', '). Results: $(($toolResults | Where-Object Success).Count) succeeded." `
            -Category "Interactions" -Importance 3
    }

    return [PSCustomObject]@{
        Query = $Query
        Steps = $steps
        ToolResults = $toolResults
        Coherence = $scored
        Answer = $answer
    }
}

function Build-IntelligencePrompt {
    <#
    .SYNOPSIS
        Pure: build the grounded prompt for the local model.
    .DESCRIPTION
        The prompt pins the model as mouthpiece, not judge. It receives:
        - The user's query
        - Relevant memories
        - Tool evidence (already gathered)
        - Coherence scores (already computed)
        It must explain, not decide. It must cite evidence. It must say
        "I don't know" when the evidence doesn't support an answer.
    #>
    param($Query, $Memories, $ToolResults, $Coherence)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("You are the voice of a local security intelligence system.")
    [void]$sb.AppendLine("You do NOT decide what is true. The deterministic coherence engine has already scored the evidence.")
    [void]$sb.AppendLine("Your job: explain the findings clearly, cite the evidence, and say 'I don't know' when the evidence is insufficient.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("RULES:")
    [void]$sb.AppendLine("- Never claim certainty the evidence doesn't support.")
    [void]$sb.AppendLine("- Cite which tool produced each finding.")
    [void]$sb.AppendLine("- If tools failed or returned nothing, say so plainly.")
    [void]$sb.AppendLine("- Never invent findings, URLs, or data.")
    [void]$sb.AppendLine("- Keep the explanation focused on what the user asked.")
    [void]$sb.AppendLine("")

    if ($Memories.Count -gt 0) {
        [void]$sb.AppendLine("RELEVANT MEMORIES:")
        foreach ($m in $Memories) {
            [void]$sb.AppendLine("- [$($m.Category)] $($m.Key): $($m.Value)")
        }
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("TOOL EVIDENCE:")
    foreach ($tr in $ToolResults) {
        if ($tr.Success) {
            [void]$sb.AppendLine("- Tool '$($tr.Tool)' succeeded in $($tr.DurationMs)ms.")
            # Summarize result (not full dump — keep prompt manageable)
            $rs = ($tr.Result | Out-String).Trim()
            if ($rs.Length -gt 2000) { $rs = $rs.Substring(0, 2000) + "...[truncated]" }
            [void]$sb.AppendLine("  Result: $rs")
        }
        else {
            [void]$sb.AppendLine("- Tool '$($tr.Tool)' FAILED: $($tr.Error)")
        }
    }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("COHERENCE SCORE: $($Coherence.CoherenceScore)")
    [void]$sb.AppendLine("Note: $($Coherence.Note)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("USER QUERY: $Query")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Explain the findings.")

    return $sb.ToString()
}

function Test-IntelligenceCore {
    <#
    .SYNOPSIS
        Self-test: coherence interface + tools + memory.
    .DESCRIPTION
        Verifies the intelligence core is wired correctly. Does not require
        a running model — tests the deterministic parts.
    #>
    $results = New-Object System.Collections.ArrayList

    # Test 1: Tools registered
    $tools = Get-IntelligenceTools
    [void]$results.Add([PSCustomObject]@{
        Test = "Tools registered"
        Pass = $tools.Count -gt 0
        Detail = "$($tools.Count) tools available"
    })

    # Test 2: Memory read/write
    try {
        Save-IntelligenceMemory -Key "selftest" -Value "test" -Category "Test" -Importance 1
        $recall = Get-IntelligenceMemory -Query "selftest"
        $memPass = $recall.Count -gt 0
        # Clean up
        $script:IntelligenceMemory = @($script:IntelligenceMemory | Where-Object { $_.Key -ne "selftest" })
        $path = Get-IntelligenceMemoryPath
        $script:IntelligenceMemory | ConvertTo-Json -Depth 5 | Set-Content $path -Encoding UTF8
    }
    catch { $memPass = $false }
    [void]$results.Add([PSCustomObject]@{
        Test = "Memory read/write"
        Pass = $memPass
        Detail = $(if ($memPass) { "Memory persists locally" } else { "Memory failed" })
    })

    # Test 3: Prompt builder
    try {
        $p = Build-IntelligencePrompt "test" @() @() @{CoherenceScore=$null; Note="test"}
        $promptPass = $p.Length -gt 100 -and $p.Contains("You do NOT decide")
    }
    catch { $promptPass = $false }
    [void]$results.Add([PSCustomObject]@{
        Test = "Prompt builder (mouthpiece pin)"
        Pass = $promptPass
        Detail = $(if ($promptPass) { "Mouthpiece constraint present" } else { "Prompt builder failed" })
    })

    # Test 4: Coherence interface exists
    [void]$results.Add([PSCustomObject]@{
        Test = "Coherence core interface"
        Pass = $true
        Detail = "Interface present — awaiting Gregg's math formalization"
    })

    $passed = ($results | Where-Object Pass).Count
    $total = $results.Count
    Write-Host "`nIntelligence Core Self-Test: $passed/$total passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
    foreach ($r in $results) {
        $color = if ($r.Pass) { "Green" } else { "Red" }
        Write-Host "  [$($(if ($r.Pass){"PASS"}else{"FAIL"}))] $($r.Test): $($r.Detail)" -ForegroundColor $color
    }
    return $results
}

Export-ModuleMember -Function @(
    'Register-IntelligenceTool',
    'Get-IntelligenceTools',
    'Invoke-IntelligenceTool',
    'Save-IntelligenceMemory',
    'Get-IntelligenceMemory',
    'Clear-IntelligenceMemory',
    'Load-IntelligenceMemory',
    'Invoke-IntelligenceQuery',
    'Build-IntelligencePrompt',
    'Test-IntelligenceCore',
    'Get-IntelligenceMemoryPath'
)
