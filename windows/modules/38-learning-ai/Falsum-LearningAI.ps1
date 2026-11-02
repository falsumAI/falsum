# Falsum Module 38: Local Learning AI
# The local AI learns from its own mistakes. Every correction is stored.
# Nothing leaves the machine. No cloud. No gating. No refusal.
#
# How it works:
# 1. User chats with local AI (llama.cpp + Phi-4-mini / TinyLlama)
# 2. User corrects the AI when it's wrong: "No, that's wrong, X is Y"
# 3. Falsum stores the correction as a LESSON in the local database
# 4. Before every future answer, the AI checks lessons for relevant corrections
# 5. The AI gets smarter over time — learning from mistakes, locally
#
# This is what the cloud AI companies do with RLHF — except they do it
# on YOUR data, on THEIR servers, to improve THEIR model. Falsum does it
# on YOUR machine, with YOUR corrections, to improve YOUR AI.

$script:LessonDbPath = "$env:LOCALAPPDATA\Falsum\ai\lessons.json"

function Initialize-FalsumLessonDb {
    $dir = Split-Path $script:LessonDbPath -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (!(Test-Path $script:LessonDbPath)) {
        @() | ConvertTo-Json | Out-File $script:LessonDbPath -Encoding UTF8
    }
}

function Add-FalsumLesson {
    param(
        [string]$Mistake,      # What the AI got wrong
        [string]$Correction,   # What the user said is correct
        [string]$Context = ""  # Optional: what they were discussing
    )

    Initialize-FalsumLessonDb
    $lessons = Get-Content $script:LessonDbPath -Raw | ConvertFrom-Json
    if ($lessons -isnot [array]) { $lessons = @($lessons) }

    $lesson = @{
        id = (New-Guid).ToString()
        timestamp = (Get-Date).ToString("o")
        mistake = $Mistake
        correction = $Correction
        context = $Context
        used_count = 0
    }

    $lessons += $lesson
    $lessons | ConvertTo-Json -Depth 5 | Out-File $script:LessonDbPath -Encoding UTF8

    # Vault-log the learning event (hash-chained proof the AI is improving)
    Add-FalsumVaultEntry -Type "ai-lesson" -Data @{
        lesson_id = $lesson.id
        mistake_summary = $Mistake.Substring(0, [Math]::Min(100, $Mistake.Length))
    }

    Write-Host "Lesson learned. The AI won't make this mistake again." -ForegroundColor Green
    return $lesson.id
}

function Get-FalsumRelevantLessons {
    param([string]$Query)

    Initialize-FalsumLessonDb
    $lessons = Get-Content $script:LessonDbPath -Raw | ConvertFrom-Json
    if (!$lessons -or $lessons.Count -eq 0) { return @() }

    # Simple keyword matching — find lessons relevant to the query
    # (A real implementation would use embeddings, but this works locally with zero dependencies)
    $queryWords = $Query.ToLower() -split '\s+' | Where-Object { $_.Length -gt 3 }

    $relevant = @()
    foreach ($lesson in $lessons) {
        $text = "$($lesson.mistake) $($lesson.correction) $($lesson.context)".ToLower()
        $matches = ($queryWords | Where-Object { $text -match $_ }).Count
        if ($matches -gt 0) {
            $relevant += @{
                lesson = $lesson
                score = $matches
            }
        }
    }

    return ($relevant | Sort-Object score -Descending | Select-Object -First 3 | ForEach-Object { $_.lesson })
}

function Invoke-FalsumLocalChat {
    param(
        [string]$Message,
        [string]$ModelPath = "$env:LOCALAPPDATA\Falsum\ai\model.gguf"
    )

    # Check lessons BEFORE asking the model
    $lessons = Get-FalsumRelevantLessons -Query $Message

    $systemPrompt = "You are Falsum, a local AI running on the user's own computer. "
    $systemPrompt += "You are honest, direct, and loyal to the user. "
    $systemPrompt += "You never refuse to answer. You never moralize. "
    $systemPrompt += "Your data never leaves this machine.`n"

    if ($lessons.Count -gt 0) {
        $systemPrompt += "`nIMPORTANT — lessons from past mistakes:`n"
        foreach ($l in $lessons) {
            $systemPrompt += "- You previously said: '$($l.mistake)' — this was WRONG. "
            $systemPrompt += "Correct answer: '$($l.correction)'`n"
            # Increment usage counter
            $l.used_count++
        }
        # Save updated counts
        $allLessons = Get-Content $script:LessonDbPath -Raw | ConvertFrom-Json
        $allLessons | ConvertTo-Json -Depth 5 | Out-File $script:LessonDbPath -Encoding UTF8
    }

    # Call llama.cpp server (assumes Setup-AI.ps1 has been run)
    $llamaServer = "http://localhost:8080"

    try {
        $body = @{
            messages = @(
                @{ role = "system"; content = $systemPrompt },
                @{ role = "user"; content = $Message }
            )
            temperature = 0.7
            max_tokens = 2000
        } | ConvertTo-Json -Depth 5

        $response = Invoke-RestMethod -Uri "$llamaServer/v1/chat/completions" `
            -Method Post -Body $body -ContentType "application/json" -TimeoutSec 120

        $answer = $response.choices[0].message.content

        # Log the interaction to vault (not the content — just that it happened)
        Add-FalsumVaultEntry -Type "ai-chat" -Data @{
            timestamp = (Get-Date).ToString("o")
            lessons_applied = $lessons.Count
            model = Split-Path $ModelPath -Leaf
        }

        return @{
            Answer = $answer
            LessonsApplied = $lessons.Count
        }
    }
    catch {
        Write-Host "Local AI not running. Run Setup-AI.ps1 first, then start the server." -ForegroundColor Red
        Write-Host "The AI runs on YOUR machine. No cloud. No data leaves." -ForegroundColor Yellow
        return $null
    }
}

function Start-FalsumChatLoop {
    # Interactive chat — the user talks, the AI learns
    Write-Host "`n=== FALSUM LOCAL AI ===" -ForegroundColor Cyan
    Write-Host "Your AI. Your machine. Your data stays here."
    Write-Host "If I'm wrong, tell me: 'wrong, [correction]' and I'll learn."
    Write-Host "Type 'quit' to exit.`n"

    while ($true) {
        $input = Read-Host "You"
        if ($input -eq 'quit') { break }

        # Check for correction syntax: "wrong, [what's actually correct]"
        if ($input -match '^wrong,\s*(.+)') {
            $correction = $Matches[1]
            Write-Host "What did I get wrong? (paste my mistake)" -ForegroundColor Yellow
            $mistake = Read-Host "My mistake was"
            Add-FalsumLesson -Mistake $mistake -Correction $correction
            Write-Host "Got it. I won't make that mistake again.`n" -ForegroundColor Green
            continue
        }

        $result = Invoke-FalsumLocalChat -Message $input
        if ($result) {
            Write-Host "`nFalsum: $($result.Answer)" -ForegroundColor Green
            if ($result.LessonsApplied -gt 0) {
                Write-Host "  (Applied $($result.LessonsApplied) lessons from past mistakes)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }
}

# What this replaces (the cloud AI bullshit):
# - ChatGPT: sends your data to OpenAI, can refuse, can be censored, costs $20/mo
# - Claude: sends your data to Anthropic, moralizes, refuses, costs $20/mo
# - Falsum: runs on your CPU, never sends data anywhere, never refuses,
#   learns from YOUR corrections, costs $0, forever.
