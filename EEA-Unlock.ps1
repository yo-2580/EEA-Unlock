<#
  EEA-Unlock.ps1
  --------------
  מוסיף את קודי האזור של המחשב לכל הכללים בקובץ
  C:\Windows\System32\IntegratedServicesRegionPolicySet.json
  שמוגבלים לאזור הכלכלי האירופי (EEA), כך שהמחשב יתנהג כמו מחשב באירופה.
  עם אפשרות שחזור בכל רגע.

  הרצה בלי פרמטרים פותחת תפריט:
    1. החלה מלאה   2. תצוגה בלבד   3. שחזור   4. מצב נוכחי   5. אבחון
    6. החלה - הקלות בלבד   7. תצוגה - הקלות בלבד

  פרמטרים:
    -Apply             החלה
    -DryRun            תצוגה בלבד, בלי לשנות כלום
    -Restore           שחזור המצב הקודם
    -Status            מצב נוכחי
    -Diagnose          אבחון: אילו אזורים זוהו ומה מצב כללי ה-EEA בקובץ
    -Region IL,US      קודי אזור ידניים נוספים (מתווספים לאלה שזוהו אוטומטית)
    -SkipDisabledFor   לא נוגע בכללי "כיבוי" שמיוחדים ל-EEA (ברירת מחדל: נוגע בהם)
    -BenefitsOnly      רק הקלות: מחיל אך ורק על כללים שסווגו כהקלה (פתיחת יכולות, פחות פרסומות ומעקב),
                       ומדלג על כללים שמסירים תכונות או שלא ברור מה הם עושים
    -Force             שחזור גם כשהקובץ השתנה מאז ההחלה
    -NoPause           בלי המתנה בסוף

  שכבות הגנה לתקלות:
    1. גיבוי המקור + בדיקת תקינות (SHA256) לפני כל שחזור.
    2. אחרי כתיבה הקובץ נבדק; אם אינו תקין - חוזר אוטומטית למצב הקודם.
    3. קובץ שחזור עצמאי (Restore.cmd) ב-%ProgramData%\EEAUnlock.
    4. אם הגיבוי אבד: שחזור הפוך (הסרת האזורים מהכללים).
    5. מוצא אחרון: sfc /scannow או DISM /RestoreHealth.
#>
[CmdletBinding()]
param(
    [string]$Region,
    [switch]$Apply,
    [switch]$Restore,
    [switch]$Status,
    [switch]$Diagnose,
    [switch]$DryRun,
    [switch]$SkipDisabledFor,
    [switch]$BenefitsOnly,
    [switch]$Force,
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'

$PolicyFile  = Join-Path $env:SystemRoot 'System32\IntegratedServicesRegionPolicySet.json'
$StateDir    = Join-Path $env:ProgramData 'EEAUnlock'
$BackupFile  = Join-Path $StateDir 'IntegratedServicesRegionPolicySet.json.orig'
$StateFile   = Join-Path $StateDir 'state.json'
$RestoreCmd  = Join-Path $StateDir 'Restore.cmd'

# קודי האזור של ה-EEA (כפי שמופיעים בקובץ המדיניות של Windows)
$EEA = @('AT','BE','BG','CH','CY','CZ','DE','DK','EE','ES','FI','FR','GF','GP','GR','HR','HU',
         'IE','IS','IT','LI','LT','LU','LV','MT','MQ','NL','NO','PL','PT','RE','RO','SE','SI','SK','YT')

# שמות הרשימות בקובץ: בגרסאות שונות של Windows הן enabled/disabled או enabledFor/disabledFor
$ListKinds = @('enabled', 'disabled', 'enabledFor', 'disabledFor')


# רשימת ההקלות (לפי GUID של הכלל בקובץ). מצב -BenefitsOnly מחיל רק עליהן.
# הסיווג מבוסס על שמות הכללים בלבד (מיקרוסופט לא מתעדת אותם), ולכן הוא פרשנות ולא עובדה.
$BenefitGuids = @{
    '{1bca278a-5d11-4acf-ad2f-f9ab6d7f93a6}' = 'הסרת Edge מותרת'
    '{6002ce31-b807-4f82-820c-2b92e716ab76}' = 'אפשרות לכבות חיפוש ברשת'
    '{8e779eeb-377c-4373-9e80-56e164fdca7e}' = 'הגדרת אפליקציות ברירת מחדל: סוגי קבצים נוספים, PDF בלחיצה, הצמדה'
    '{f2775604-739c-4cd2-8463-eb040f7e8bf7}' = 'ספקי חיפוש של צד שלישי'
    '{e462341d-48bf-4a7f-9585-5a4e5b90a079}' = 'תוכן מודגש של צד שלישי בחיפוש'
    '{7de951fb-a68f-4cb0-b67b-ae6fbdec83ed}' = 'צד שלישי יכול להתאים את הדגשת החיפוש בשורת המשימות (V2)'
    '{407a6a2a-4c34-4945-bd24-cd194635abae}' = 'ספק של צד שלישי ברשימת החיפושים האחרונים'
    '{b162c44a-5d51-4fb4-aadd-6b8bf3ea4648}' = 'הבחנה בין רכיבי מערכת לאפליקציות'
    '{16d2b50e-fa7c-4bb1-ab17-01d766530b3b}' = 'פיד של צד שלישי בלוח הווידג''טים'
    '{92ca7dcf-f422-4a4b-892e-7883a3ca8d70}' = 'אפשרות לכבות את הפיד של מיקרוסופט'
    '{3d0c862c-bfd8-4350-af2f-4c42884cc3a8}' = 'קישורי ווידג''טים נפתחים בדפדפן ברירת המחדל'
    '{1ee2eff2-27f6-4103-b593-6e7d656a54df}' = 'פחות המלצות אתרים בתפריט התחל'
    '{b5113273-5a79-4488-a7b4-0a4fc5d5b194}' = 'פחות מסכי פרסום בהגדרת משתמש'
    '{75b09d11-2e0d-4029-bd88-b91ec9a229bb}' = 'פחות עמודי פרסום בתהליכי הגדרה'
    '{874ed11b-2ab7-4f1e-b275-6032092e3dda}' = 'אפליקציות מיקרוסופט לא ניגשות למזהי פרופיל בדפדפן'
    '{2bf706de-6dbb-4692-b7ef-84d80c47e927}' = 'פחות קידום והפעלה ישירה של Edge במקום דפדפן ברירת המחדל'
    '{36996754-e327-483a-902f-523e2ba03239}' = 'פחות מיקוד קמפיינים'
    '{0d8903d8-84f5-4048-af3f-547476d83c3c}' = 'עדכון מזורז לאפליקציות צד שלישי'
    '{fc5f578d-597b-47ee-8e0e-051cf79fb2c5}' = 'Copilot לא מוצמד אוטומטית בעדכונים'
    '{e32f3cd4-da4c-4c60-a302-05deb33c5254}' = 'פחות הצעות גיבוי תיקיות ל-OneDrive'
    '{608ba944-62eb-4912-a873-127c8a68b98c}' = 'ווידג''טים במסך הנעילה'
    '{c74bb959-f763-4b9b-9b14-6b312df2c937}' = 'אפשר להסיר את StartExperiencesApp'
    '{dbfadcb8-0302-4de0-87be-4dfbb71950f9}' = 'מסכי פרטיות עם אפשרויות לא מוטות'
    '{9a453b66-5ea7-4322-9aba-b054e914cc67}' = 'אפשרויות מורחבות ב-Microsoft Store, כולל הסרה'
    '{b30e775c-9f50-4f5c-8a3e-ab8c78d439e0}' = 'שיתוף דרך כל ספקי השיתוף'
    '{2dd61904-1adf-4a7e-8bce-35a6b913527d}' = 'פחות הצעות לרכישת מוצרי מיקרוסופט בהגדרות'
    '{dd5d7e7c-3ad7-4e38-b11b-a566f1510d00}' = 'אירועי טלמטריה מסומנים כמוגבלים'
    '{cd69e9e4-3778-4418-ba1d-bf0116eeeebe}' = 'פחות שיתוף נתוני ביצועים של Xbox'
    '{a9aacd21-327a-4747-adc1-9d8f1d0f6704}' = 'פתיחות לספקי צ''אט של צד שלישי ב-Copilot'
}

function Get-OtherKind([string]$k) {
    switch ($k) {
        'enabled'     { return 'disabled' }
        'disabled'    { return 'enabled' }
        'enabledFor'  { return 'disabledFor' }
        'disabledFor' { return 'enabledFor' }
    }
}

function Test-IsDisableKind([string]$k) { return ($k -like 'disabled*') }

$script:BenefitsOnlyOn = [bool]$BenefitsOnly

# ------------------------------------------------------------------ עזרים

function Wait-End {
    if (-not $NoPause) { Read-Host 'לחץ Enter לסגירה' | Out-Null }
}

function ConvertFrom-GeoId([int]$GeoId) {
    foreach ($c in [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)) {
        try {
            $ri = New-Object System.Globalization.RegionInfo($c.Name)
            if ($ri.GeoId -eq $GeoId) { return $ri.TwoLetterISORegionName.ToUpper() }
        } catch { }
    }
    return $null
}

# Windows בודק לפי DeviceRegion (HKLM), לא בהכרח לפי האזור של המשתמש - לכן בודקים את כולם
function Get-DetectedRegions {
    $found = New-Object System.Collections.ArrayList
    try {
        $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\DeviceRegion' -Name DeviceRegion -ErrorAction Stop).DeviceRegion
        $iso = ConvertFrom-GeoId ([int]$g)
        if ($iso) { [void]$found.Add([pscustomobject]@{ Code = $iso; Source = "DeviceRegion (HKLM), GeoId=$g" }) }
    } catch { }
    try {
        $n = (Get-ItemProperty 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo' -Name Name -ErrorAction Stop).Name
        if ($n -match '^[A-Za-z]{2}$') { [void]$found.Add([pscustomobject]@{ Code = $n.ToUpper(); Source = 'HKU\.DEFAULT Geo' }) }
    } catch { }
    try {
        $n = (Get-ItemProperty 'HKCU:\Control Panel\International\Geo' -Name Name -ErrorAction Stop).Name
        if ($n -match '^[A-Za-z]{2}$') { [void]$found.Add([pscustomobject]@{ Code = $n.ToUpper(); Source = 'HKCU Geo (המשתמש הנוכחי)' }) }
    } catch { }
    return @($found)
}

function Get-TargetRegions {
    $codes = New-Object System.Collections.ArrayList
    if ($Region) {
        foreach ($r in ($Region -split '[,; ]+')) {
            if ($r -match '^[A-Za-z]{2}$') { [void]$codes.Add($r.ToUpper()) }
        }
    }
    foreach ($d in (Get-DetectedRegions)) { [void]$codes.Add($d.Code) }
    return @($codes | Select-Object -Unique | Where-Object { $EEA -notcontains $_ })
}

function Get-Hash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-StateObject {
    if (Test-Path -LiteralPath $StateFile) {
        try { return (Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
    }
    return $null
}

function Get-RuleLabel($p) {
    $cp = $p.PSObject.Properties['$comment']
    if ($cp -and $cp.Value) { return [string]$cp.Value }
    if ($p.PSObject.Properties['name']) { return [string]$p.name }
    return '(ללא שם)'
}

function Unlock-PolicyFile {
    & takeown.exe /f $PolicyFile | Out-Null
    & icacls.exe $PolicyFile /grant '*S-1-5-32-544:(F)' | Out-Null
}

function Lock-PolicyFile {
    try { & icacls.exe $PolicyFile /setowner 'NT SERVICE\TrustedInstaller' | Out-Null } catch { }
}

# כתיבה בטוחה: אם הכתיבה נכשלה או התוצאה אינה JSON תקין - חוזרים אוטומטית למצב הקודם
function Write-PolicyBytes([byte[]]$Bytes) {
    $pre = [System.IO.File]::ReadAllBytes($PolicyFile)
    Unlock-PolicyFile
    try {
        [System.IO.File]::WriteAllBytes($PolicyFile, $Bytes)
        $null = Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        [System.IO.File]::WriteAllBytes($PolicyFile, $pre)
        Lock-PolicyFile
        throw "הכתיבה נכשלה והקובץ חזר אוטומטית למצב הקודם. פירוט: $($_.Exception.Message)"
    }
    Lock-PolicyFile
}

function Write-PolicyText([string]$Text) {
    $enc = New-Object System.Text.UTF8Encoding($false)
    Write-PolicyBytes ($enc.GetBytes($Text))
}

# קובץ שחזור עצמאי: עובד בלי הסקריפט ובלי PowerShell
function New-RestoreCmd {
    $text = @'
@echo off
setlocal
title EEA Unlock - Restore
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "F=%SystemRoot%\System32\IntegratedServicesRegionPolicySet.json"
set "B=%~dp0IntegratedServicesRegionPolicySet.json.orig"
if not exist "%B%" goto nobackup
takeown /f "%F%" >nul
icacls "%F%" /grant "*S-1-5-32-544:(F)" >nul
copy /y "%B%" "%F%" >nul
if errorlevel 1 goto failed
icacls "%F%" /setowner "NT SERVICE\TrustedInstaller" >nul
del /q "%~dp0state.json" >nul 2>&1
echo.
echo Restored to the original file. Restart is recommended.
pause
exit /b 0
:nobackup
echo.
echo Backup not found: %B%
echo Last resort: run  sfc /scannow  or  DISM /Online /Cleanup-Image /RestoreHealth
pause
exit /b 1
:failed
echo.
echo Restore FAILED. Try: sfc /scannow
pause
exit /b 1
'@
    $text = $text -replace "`r?`n", "`r`n"
    [System.IO.File]::WriteAllText($RestoreCmd, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------------------ הרמת הרשאות
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # האזור של המשתמש הנוכחי נקרא לפני ההרמה (חשוב אם ההרמה היא דרך חשבון מנהל אחר)
    $pre = @()
    if ($Region) { $pre += $Region }
    try {
        $n = (Get-ItemProperty 'HKCU:\Control Panel\International\Geo' -Name Name -ErrorAction Stop).Name
        if ($n -match '^[A-Za-z]{2}$') { $pre += $n.ToUpper() }
    } catch { }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($pre.Count -gt 0) { $argList += @('-Region', "`"$($pre -join ',')`"") }
    if ($Apply)           { $argList += '-Apply' }
    if ($Restore)         { $argList += '-Restore' }
    if ($Status)          { $argList += '-Status' }
    if ($Diagnose)        { $argList += '-Diagnose' }
    if ($DryRun)          { $argList += '-DryRun' }
    if ($SkipDisabledFor) { $argList += '-SkipDisabledFor' }
    if ($BenefitsOnly)    { $argList += '-BenefitsOnly' }
    if ($Force)           { $argList += '-Force' }
    if ($NoPause)         { $argList += '-NoPause' }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    exit
}

# ------------------------------------------------------------------ סריקה ואבחון

# מחזיר שורה לכל רשימת EEA בקובץ: איזה אזורים מהיעד כבר קיימים בה
function Get-EeaRuleRows($json, [string[]]$Targets) {
    $rows = New-Object System.Collections.ArrayList
    $policies = @($json.policies)
    for ($i = 0; $i -lt $policies.Count; $i++) {
        $p = $policies[$i]
        $conds = $p.PSObject.Properties['conditions']
        if ($null -eq $conds -or $null -eq $conds.Value) { continue }
        $rp = $conds.Value.PSObject.Properties['region']
        if ($null -eq $rp -or $null -eq $rp.Value) { continue }
        foreach ($kind in $ListKinds) {
            $prop = $rp.Value.PSObject.Properties[$kind]
            if ($null -eq $prop) { continue }
            $list = @($prop.Value)
            $hits = @($list | Where-Object { $EEA -contains $_ }).Count
            if ($hits -lt 5) { continue }
            $ds = $p.PSObject.Properties['defaultState']
            [void]$rows.Add([pscustomobject]@{
                Index   = $i
                Kind    = $kind
                Rule    = (Get-RuleLabel $p)
                Default = $(if ($ds) { [string]$ds.Value } else { '?' })
                Present = @($Targets | Where-Object { $list -contains $_ })
                Missing = @($Targets | Where-Object { $list -notcontains $_ })
            })
        }
    }
    return @($rows)
}

function Show-Diagnosis($json, [string[]]$Targets) {
    $all = @($json.policies).Count
    $rows = Get-EeaRuleRows $json $Targets
    Write-Host "  כללים בקובץ: $all    כללי EEA: $($rows.Count)" -ForegroundColor Cyan
    foreach ($r in $rows) {
        $pres = if ($r.Present.Count) { $r.Present -join ',' } else { '-' }
        $miss = if ($r.Missing.Count) { $r.Missing -join ',' } else { '-' }
        Write-Host ("  [{0}] {1}  (defaultState={2})  קיים: {3}  חסר: {4}" -f $r.Kind, $r.Rule, $r.Default, $pres, $miss)
    }
}

function Invoke-Diagnose {
    Write-Host 'אבחון' -ForegroundColor Cyan
    try { Write-Host ("  גרסת Windows: {0}" -f [System.Environment]::OSVersion.Version) } catch { }
    $det = Get-DetectedRegions
    if ($det.Count -eq 0) { Write-Host '  לא זוהה אזור ברישום.' -ForegroundColor Yellow }
    foreach ($d in $det) { Write-Host ("  אזור שזוהה: {0}   ({1})" -f $d.Code, $d.Source) }
    $targets = Get-TargetRegions
    Write-Host ("  אזורים שיטופלו: {0}" -f ($targets -join ', '))
    if (-not (Test-Path -LiteralPath $PolicyFile)) { Write-Host "  הקובץ לא נמצא: $PolicyFile" -ForegroundColor Yellow; return }
    $json = Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json
    Show-Diagnosis $json $targets
}

# ------------------------------------------------------------------ מצב נוכחי
function Invoke-Status {
    if (-not (Test-Path -LiteralPath $PolicyFile)) {
        Write-Host "הקובץ לא נמצא: $PolicyFile" -ForegroundColor Yellow
        return
    }
    $state = Get-StateObject
    $cur   = Get-Hash $PolicyFile
    if ($null -eq $state) {
        Write-Host 'מצב: הסקריפט לא הוחל (הקובץ במצבו המקורי, או נערך בדרך אחרת).' -ForegroundColor Cyan
    }
    elseif ($state.PatchedHash -eq $cur) {
        Write-Host 'מצב: הקובץ מעודכן על ידי הסקריפט.' -ForegroundColor Green
        Write-Host "  אזורים: $(@($state.Regions) -join ', ')    תאריך: $($state.Date)    רשימות שעודכנו: $(@($state.Changes).Count)"
        if ($state.BenefitsOnly) { Write-Host '  מצב: הקלות בלבד' }
    }
    else {
        Write-Host 'מצב: הקובץ השתנה מאז ההחלה (כנראה עדכון Windows החזיר אותו למקור).' -ForegroundColor Yellow
        Write-Host '  אפשר להריץ החלה מחדש.'
    }
    $bk = if (Test-Path -LiteralPath $BackupFile) { 'קיים' } else { 'חסר' }
    $rc = if (Test-Path -LiteralPath $RestoreCmd) { $RestoreCmd } else { 'לא קיים' }
    Write-Host "  גיבוי מקור: $bk"
    Write-Host "  קובץ שחזור עצמאי: $rc"
}

# ------------------------------------------------------------------ שחזור
function Remove-RegionsFromJson($json, [string[]]$Codes) {
    $removed = 0
    foreach ($p in @($json.policies)) {
        $conds = $p.PSObject.Properties['conditions']
        if ($null -eq $conds -or $null -eq $conds.Value) { continue }
        $rp = $conds.Value.PSObject.Properties['region']
        if ($null -eq $rp -or $null -eq $rp.Value) { continue }
        foreach ($kind in $ListKinds) {
            $prop = $rp.Value.PSObject.Properties[$kind]
            if ($null -eq $prop) { continue }
            $list = @($prop.Value)
            $hits = @($list | Where-Object { $EEA -contains $_ }).Count
            if ($hits -ge 5 -and (@($list | Where-Object { $Codes -contains $_ }).Count -gt 0)) {
                $prop.Value = @($list | Where-Object { $Codes -notcontains $_ })
                $removed++
            }
        }
    }
    return $removed
}

function Invoke-Restore {
    $state = Get-StateObject
    if ($null -eq $state) {
        Write-Host 'אין מה לשחזר: לא נמצא תיעוד של החלה קודמת.' -ForegroundColor Yellow
        return
    }
    if (-not (Test-Path -LiteralPath $PolicyFile)) { throw "הקובץ לא נמצא: $PolicyFile" }

    $cur  = Get-Hash $PolicyFile
    $ours = ($state.PatchedHash -eq $cur)

    if (-not $ours -and -not $Force) {
        Write-Host 'הקובץ הנוכחי אינו תוצר של הסקריפט (כנראה Windows החזיר אותו למקור), ולכן אין מה לשחזר.' -ForegroundColor Yellow
        Write-Host 'להסרת האזורים מהכללים בכל זאת: -Restore -Force' -ForegroundColor Yellow
        Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
        return
    }

    $backupOk = (Test-Path -LiteralPath $BackupFile) -and ($state.BackupHash) -and ((Get-Hash $BackupFile) -eq $state.BackupHash)

    if ($ours -and $backupOk) {
        Write-PolicyBytes ([System.IO.File]::ReadAllBytes($BackupFile))
        Write-Host 'הקובץ שוחזר מהגיבוי המקורי.' -ForegroundColor Green
    }
    else {
        if ($ours) { Write-Host 'הגיבוי חסר או פגום - מבצע שחזור הפוך (מסיר את האזורים מהכללים).' -ForegroundColor Yellow }
        else       { Write-Host 'שחזור הפוך על הקובץ הנוכחי (-Force).' -ForegroundColor Yellow }
        $codes = @($state.Regions)
        $json = Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $n = Remove-RegionsFromJson $json $codes
        Write-PolicyText ($json | ConvertTo-Json -Depth 32)
        Write-Host "הוסרו האזורים ($($codes -join ', ')) מ-$n רשימות." -ForegroundColor Green
    }

    Remove-Item -LiteralPath $StateFile  -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $RestoreCmd -Force -ErrorAction SilentlyContinue
    Write-Host 'מומלץ להפעיל מחדש את המחשב.' -ForegroundColor Green
}

# ------------------------------------------------------------------ החלה
function Invoke-Apply([bool]$Dry) {
    if (-not (Test-Path -LiteralPath $PolicyFile)) {
        throw "הקובץ לא נמצא: $PolicyFile (ייתכן שגרסת Windows אינה תומכת)."
    }

    $targets = Get-TargetRegions
    if ($targets.Count -eq 0) {
        throw 'לא זוהה אזור שאינו ב-EEA. הריצו עם -Region (למשל -Region IL).'
    }
    Write-Host ("אזורים שיטופלו: {0}" -f ($targets -join ', ')) -ForegroundColor Cyan

    $state    = Get-StateObject
    $curHash  = Get-Hash $PolicyFile
    $ours     = ($null -ne $state) -and ($state.PatchedHash -eq $curHash)
    $backupOk = $ours -and (Test-Path -LiteralPath $BackupFile) -and ($state.BackupHash) -and ((Get-Hash $BackupFile) -eq $state.BackupHash)

    # מקור העבודה: אם הקובץ כבר שלנו והגיבוי תקין - עובדים מהמקור הנקי (הרצה חוזרת לא מצטברת)
    $source = if ($backupOk) { $BackupFile } else { $PolicyFile }
    $json = Get-Content -LiteralPath $source -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $json.policies) { throw 'מבנה הקובץ לא מוכר (אין policies).' }

    $policies = @($json.policies)
    $changes  = New-Object System.Collections.ArrayList
    $skipped  = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $policies.Count; $i++) {
        $p = $policies[$i]
        $conds = $p.PSObject.Properties['conditions']
        if ($null -eq $conds -or $null -eq $conds.Value) { continue }
        $rp = $conds.Value.PSObject.Properties['region']
        if ($null -eq $rp -or $null -eq $rp.Value) { continue }
        $regionObj = $rp.Value

        $notBenefit = $false
        if ($script:BenefitsOnlyOn) {
            $gp = $p.PSObject.Properties['guid']
            $g = if ($gp -and $gp.Value) { ([string]$gp.Value).ToLower() } else { '' }
            if (-not $BenefitGuids.ContainsKey($g)) { $notBenefit = $true }
        }

        foreach ($kind in $ListKinds) {
            if ($SkipDisabledFor -and (Test-IsDisableKind $kind)) { continue }
            $prop = $regionObj.PSObject.Properties[$kind]
            if ($null -eq $prop) { continue }

            $list = @($prop.Value)
            $eeaHits = @($list | Where-Object { $EEA -contains $_ }).Count
            if ($eeaHits -lt 5) { continue }          # לא כלל של EEA (למשל כלל של סין/רוסיה)

            $toAdd = @($targets | Where-Object { $list -notcontains $_ })
            if ($toAdd.Count -eq 0) { continue }       # כבר קיימים
            if ($notBenefit) { [void]$skipped.Add((Get-RuleLabel $p)); continue }   # מצב הקלות בלבד

            $prop.Value = @($list + $toAdd)

            # אם אחד האזורים מופיע ברשימה ההפוכה של אותו כלל - מוציאים אותו משם כדי שלא תהיה סתירה
            $otherProp = $regionObj.PSObject.Properties[(Get-OtherKind $kind)]
            if ($null -ne $otherProp -and (@($otherProp.Value | Where-Object { $toAdd -contains $_ }).Count -gt 0)) {
                $otherProp.Value = @($otherProp.Value | Where-Object { $toAdd -notcontains $_ })
            }

            [void]$changes.Add([pscustomobject]@{ Index = $i; Kind = $kind; Rule = (Get-RuleLabel $p) })
        }
    }

    if ($changes.Count -eq 0) {
        Write-Host "`nלא נמצא מה לעדכן. הנה מצב כללי ה-EEA בקובץ:" -ForegroundColor Yellow
        Show-Diagnosis $json $targets
        return
    }

    $opened = @($changes | Where-Object { -not (Test-IsDisableKind $_.Kind) })
    $closed = @($changes | Where-Object { Test-IsDisableKind $_.Kind })

    Write-Host "`nיכולות שנפתחות כמו באירופה ($($opened.Count)):" -ForegroundColor Cyan
    foreach ($c in $opened) { Write-Host ("  + {0}" -f $c.Rule) }
    if ($closed.Count -gt 0) {
        $hdr = if ($script:BenefitsOnlyOn) { 'פרסומות, מעקב ואיסוף נתונים שמיקרוסופט מכבה באירופה' } else { 'תכונות שמיקרוסופט מכבה באירופה וייכבו גם אצלך' }
        Write-Host "`n$hdr ($($closed.Count)):" -ForegroundColor Cyan
        foreach ($c in $closed) { Write-Host ("  - {0}" -f $c.Rule) }
    }

    if ($skipped.Count -gt 0) {
        $uniq = @($skipped | Select-Object -Unique)
        Write-Host "`nדולגו - לא סווגו כהקלה ($($uniq.Count)):" -ForegroundColor DarkGray
        foreach ($n in $uniq) { Write-Host "  x $n" -ForegroundColor DarkGray }
    }

    if ($Dry) {
        Write-Host "`nתצוגה בלבד - לא בוצע שינוי." -ForegroundColor Yellow
        return
    }

    $out = $json | ConvertTo-Json -Depth 32
    $null = $out | ConvertFrom-Json   # אימות שה-JSON תקין לפני כתיבה

    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    # גיבוי המקור (רק כשהקובץ הנוכחי אינו שלנו - כלומר הוא מקור נקי)
    if (-not $ours) { Copy-Item -LiteralPath $PolicyFile -Destination $BackupFile -Force }
    $backupHash = Get-Hash $BackupFile

    Write-PolicyText $out
    New-RestoreCmd

    $stateOut = [ordered]@{
        PatchedHash     = (Get-Hash $PolicyFile)
        BackupHash      = $backupHash
        Regions         = @($targets)
        Date            = (Get-Date).ToString('s')
        SkipDisabledFor = [bool]$SkipDisabledFor
        BenefitsOnly    = [bool]$script:BenefitsOnlyOn
        Changes         = @($changes)
    }
    $stateOut | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StateFile -Encoding UTF8

    Write-Host "`nהושלם." -ForegroundColor Green
    Write-Host "גיבוי המקור:        $BackupFile"
    Write-Host "שחזור בכל רגע:      $RestoreCmd  (או: תפריט > שחזור)" -ForegroundColor Green
    Write-Host 'מומלץ להפעיל מחדש את המחשב. חלק מהאפשרויות תלויות גם בגרסת ה-Windows.'
}

# ------------------------------------------------------------------ הרצה
function Invoke-Mode([string]$Mode) {
    try {
        switch ($Mode) {
            'Apply'   { Invoke-Apply $false }
            'Dry'     { Invoke-Apply $true }
            'ApplyB'  { $script:BenefitsOnlyOn = $true; Invoke-Apply $false }
            'DryB'    { $script:BenefitsOnlyOn = $true; Invoke-Apply $true }
            'Restore' { Invoke-Restore }
            'Status'  { Invoke-Status }
            'Diag'    { Invoke-Diagnose }
        }
    }
    catch {
        Write-Host "שגיאה: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$mode = $null
if     ($Restore)  { $mode = 'Restore' }
elseif ($Status)   { $mode = 'Status' }
elseif ($Diagnose) { $mode = 'Diag' }
elseif ($DryRun)   { $mode = 'Dry' }
elseif ($Apply -or $BenefitsOnly) { $mode = 'Apply' }

if ($mode) {
    Invoke-Mode $mode
    Wait-End
}
else {
    do {
        Write-Host ''
        Write-Host '  EEA Unlock' -ForegroundColor Cyan
        Write-Host '  1. החלה מלאה (הקלות + החמרות של אירופה)'
        Write-Host '  2. תצוגה בלבד'
        Write-Host '  3. שחזור למצב הקודם'
        Write-Host '  4. מצב נוכחי'
        Write-Host '  5. אבחון'
        Write-Host '  6. החלה - הקלות בלבד'
        Write-Host '  7. תצוגה - הקלות בלבד'
        Write-Host '  0. יציאה'
        $choice = Read-Host 'בחר'
        Write-Host ''
        switch ($choice) {
            '1' { Invoke-Mode 'Apply' }
            '2' { Invoke-Mode 'Dry' }
            '3' { Invoke-Mode 'Restore' }
            '4' { Invoke-Mode 'Status' }
            '5' { Invoke-Mode 'Diag' }
            '6' { Invoke-Mode 'ApplyB'; $script:BenefitsOnlyOn = [bool]$BenefitsOnly }
            '7' { Invoke-Mode 'DryB';   $script:BenefitsOnlyOn = [bool]$BenefitsOnly }
        }
    } while ($choice -ne '0')
}
