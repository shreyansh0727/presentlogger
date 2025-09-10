# Complete API Testing Script for Windows PowerShell

# Configuration
$baseUrl = "http://localhost:5000"
$headers = @{
    "Content-Type" = "application/json"
}

# Test 1: Check API Status
Write-Host "🧪 Testing API Status..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/" -Method GET
    Write-Host "✅ API is running" -ForegroundColor Green
    Write-Host "Response: $($response | ConvertTo-Json -Depth 2)" -ForegroundColor White
} catch {
    Write-Host "❌ API Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ("-" * 50)

# Test 2: Add a test student first
Write-Host "🧪 Adding Test Student..." -ForegroundColor Cyan
$studentData = @{
    rfid_uid = "RFID:90:AD:12"
    reg_no = "1578"
    name = "Shreyansh Kumar"
    class = "12A"
    parent_email = "shreyansh@example.com"
    parent_phone = "+91-9876543210"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/students" -Method POST -Headers $headers -Body $studentData
    Write-Host "✅ Student added successfully" -ForegroundColor Green
    Write-Host "Student ID: $($response.student.id)" -ForegroundColor White
} catch {
    Write-Host "⚠️ Student might already exist: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ("-" * 50)

# Test 3: Log Attendance (Your Original Test)
Write-Host "🧪 Testing Attendance Logging..." -ForegroundColor Cyan
$attendanceData = @{
    rfid_uid = "RFID:90:AD:12"
    reg_no = "1578"
    name = "Shreyansh Kumar"
    class = "12A"
    action = "ENTRY"
    timestamp = "09:30:00"
    date = "2025-09-10"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/attendance/log" -Method POST -Headers $headers -Body $attendanceData
    Write-Host "✅ Attendance logged successfully" -ForegroundColor Green
    Write-Host "Action: $($response.action)" -ForegroundColor White
    Write-Host "Time: $($response.timestamp)" -ForegroundColor White
    Write-Host "Student: $($response.student_name)" -ForegroundColor White
} catch {
    Write-Host "❌ Failed to log attendance: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Response: $($_.Exception.Response)" -ForegroundColor Red
}

Write-Host ("-" * 50)

# Test 4: Arduino Student Lookup
Write-Host "🧪 Testing Arduino Student Lookup..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/student?uid=RFID:90:AD:12" -Method GET
    if ($response.found) {
        Write-Host "✅ Student found by UID" -ForegroundColor Green
        Write-Host "Name: $($response.name)" -ForegroundColor White
        Write-Host "Present: $($response.is_present)" -ForegroundColor White
    } else {
        Write-Host "⚠️ Student not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ("-" * 50)

# Test 5: Get Daily Report
Write-Host "🧪 Testing Daily Report..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/reports/daily?date=2025-09-10" -Method GET
    Write-Host "✅ Daily report generated" -ForegroundColor Green
    Write-Host "Total Students: $($response.summary.total_students)" -ForegroundColor White
    Write-Host "Present: $($response.summary.present_count)" -ForegroundColor White
    Write-Host "Absent: $($response.summary.absent_count)" -ForegroundColor White
    Write-Host "Attendance Rate: $($response.summary.attendance_rate)%" -ForegroundColor White
} catch {
    Write-Host "❌ Report failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ("-" * 50)
Write-Host "🎉 API Testing Complete!" -ForegroundColor Green
