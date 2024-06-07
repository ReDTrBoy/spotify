param (
  [Parameter()]
  [switch]
  $UninstallSpotifyStoreEdition = (Read-Host -Prompt 'Windows Magazasi Spotify surumunu kaldirmak istiyor musunuz? (Y/N)') -eq 'y',
  [Parameter()]
  [switch]
  $UpdateSpotify
)

# Stop-Process komutundan gelen hatalari yoksay
$PSDefaultParameterValues['Stop-Process:ErrorAction'] = [System.Management.Automation.ActionPreference]::SilentlyContinue

[System.Version] $minimalSupportedSpotifyVersion = '1.2.8.923'

function DosyaAl
{
  param (
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.Uri]
    $Uri,
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]
    $HedefDosya,
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [Int32]
    $BufferBoyutu = 1,
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('KB', 'MB')]
    [String]
    $BufferBirimi = 'MB',
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [Int32]
    $ZamanAsimi = 10000
  )

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $bitsTransferKullan = $null -ne (Get-Module -Name BitsTransfer -ListAvailable) -and ($PSVersionTable.PSVersion.Major -le 5) -and ((Get-Service -Name BITS).StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled)

  if ($bitsTransferKullan)
  {
    Write-Information -MessageData 'Windows PowerShell kullaniyorsunuz, bu yuzden yedek BitTransfer yontemini kullaniyor'
    Start-BitsTransfer -Source $Uri -Destination "$($HedefDosya.FullName)"
  }
  else
  {
    $istek = [System.Net.HttpWebRequest]::Create($Uri)
    $istek.set_Timeout($ZamanAsimi) #15 saniye zaman asimi
    $yanit = $istek.GetResponse()
    $toplamUzunluk = [System.Math]::Floor($yanit.get_ContentLength() / 1024)
    $yanitAkisi = $yanit.GetResponseStream()
    $hedefAkis = New-Object -TypeName ([System.IO.FileStream]) -ArgumentList "$($HedefDosya.FullName)", Create
    switch ($BufferBirimi)
    {
      'KB' { $BufferBoyutu = $BufferBoyutu * 1024 }
      'MB' { $BufferBoyutu = $BufferBoyutu * 1024 * 1024 }
      Default { $BufferBoyutu = 1024 * 1024 }
    }
    Write-Verbose -Message "Buffer boyutu: $BufferBoyutu B ($($BufferBoyutu/("1$BufferBirimi")) $BufferBirimi)"
    $buffer = New-Object byte[] $BufferBoyutu
    $sayi = $yanitAkisi.Read($buffer, 0, $buffer.length)
    $indirilenBaytlar = $sayi
    $indirilenDosyaAdi = $Uri -split '/' | Select-Object -Last 1
    while ($sayi -gt 0)
    {
      $hedefAkis.Write($buffer, 0, $sayi)
      $sayi = $yanitAkisi.Read($buffer, 0, $buffer.length)
      $indirilenBaytlar = $indirilenBaytlar + $sayi
      Write-Progress -Activity "Dosya indiriliyor '$indirilenDosyaAdi'" -Status "Indirilen ($([System.Math]::Floor($indirilenBaytlar/1024))K of $($toplamUzunluk)K): " -PercentComplete ((([System.Math]::Floor($indirilenBaytlar / 1024)) / $toplamUzunluk) * 100)
    }

    Write-Progress -Activity "Dosya indirme islemi tamamlandi '$indirilenDosyaAdi'"

    $hedefAkis.Flush()
    $hedefAkis.Close()
    $hedefAkis.Dispose()
    $yanitAkisi.Dispose()
  }
}

function SpotifySurumunuTestEt
{
  param (
    [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [System.Version]
    $MinimalDesteklenenSurum,
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [System.Version]
    $TestEdilenSurum
  )

  process
  {
    return ($MinimalDesteklenenSurum.CompareTo($TestEdilenSurum) -le 0)
  }
}

Write-Host @'
**********************************

    ____       ____  ______     ____
   / __ \___  / __ \/_  __/____/ __ )____  __  __
  / /_/ / _ \/ / / / / / / ___/ __  / __ \/ / / /
 / _, _/  __/ /_/ / / / / /  / /_/ / /_/ / /_/ /
/_/ |_|\___/_____/ /_/ /_/  /_____/\____/\__, /_____
                                        /____/_____/

**********************************
'@

$spotifyDizini = Join-Path -Path $env:APPDATA -ChildPath 'Spotify'
$spotifyCalistirilabilir = Join-Path -Path $spotifyDizini -ChildPath 'Spotify.exe'
$spotifyUygulamalari = Join-Path -Path $spotifyDizini -ChildPath 'Apps'

[System.Version] $gercekSpotifyClientSurumu = (Get-ChildItem -LiteralPath $spotifyCalistirilabilir -ErrorAction:SilentlyContinue).VersionInfo.ProductVersionRaw

Write-Host "Spotify durduruluyor...`n"
Stop-Process -Name Spotify
Stop-Process -Name SpotifyWebHelper

if ($PSVersionTable.PSVersion.Major -ge 7)
{
  Import-Module Appx -UseWindowsPowerShell -WarningAction:SilentlyContinue
}

if (Get-AppxPackage -Name SpotifyAB.SpotifyMusic)
{
  Write-Host "Microsoft Store surumu Spotify tespit edildi, bu surum desteklenmiyor.`n"

  if ($UninstallSpotifyStoreEdition)
  {
    Write-Host "Spotify kaldiriliyor.`n"
    Get-AppxPackage -Name SpotifyAB.SpotifyMusic | Remove-AppxPackage
  }
  else
  {
    Read-Host "Cikiliyor...`nCikmak icin bir tusa basin..."
    exit
  }
}

Push-Location -LiteralPath $env:TEMP
try
{
  # Zamana gore benzersiz dizin adi
  New-Item -Type Directory -Name "BlockTheSpot-$(Get-Date -UFormat '%Y-%m-%d_%H-%M-%S')" |
  Convert-Path |
  Set-Location
}
catch
{
  Write-Output $_
  Read-Host 'Cikmak icin bir tusa basin...'
  exit
}

$spotifyYuklendi = Test-Path -LiteralPath $spotifyCalistirilabilir

if (-not $spotifyYuklendi) {
  $desteklenmeyenClientSurumu = $true
} else {
  $desteklenmeyenClientSurumu = ($gercekSpotifyClientSurumu | SpotifySurumunuTestEt -MinimalDesteklenenSurum $minimalSupportedSpotifyVersion) -eq $false
}

if (-not $UpdateSpotify -and $desteklenmeyenClientSurumu)
{
  if ((Read-Host -Prompt 'Block the Spot kurmak icin Spotify surumunuz guncellenmelidir. Devam etmek istiyor musunuz? (Y/N)') -ne 'y')
  {
    exit
  }
}

if (-not $spotifyYuklendi -or $UpdateSpotify -or $desteklenmeyenClientSurumu)
{
  Write-Host 'En son Spotify tam kurulum dosyasi indiriliyor, lutfen bekleyin...'
  $spotifyKurulumDosyaYolu = Join-Path -Path $PWD -ChildPath 'SpotifyFullSetup.exe'
  try
  {
    if ([Environment]::Is64BitOperatingSystem) { # Bilgisayarin 64-bit isletim sistemi calistirip calistirmadigini kontrol edin
      $uri = 'https://download.scdn.co/SpotifyFullSetupX64.exe'
    } else {
      $uri = 'https://download.scdn.co/SpotifyFullSetup.exe'
    }
    DosyaAl -Uri $uri -HedefDosya "$spotifyKurulumDosyaYolu"
  }
  catch
  {
    Write-Output $_
    Read-Host 'Cikmak icin bir tusa basin...'
    exit
  }
  New-Item -Path $spotifyDizini -ItemType:Directory -Force | Write-Verbose

  [System.Security.Principal.WindowsPrincipal] $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $kullaniciAdminMi = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  Write-Host 'Kurulum baslatiliyor...'
  if ($kullaniciAdminMi)
  {
    Write-Host
    Write-Host 'Zamanlanmis gorev olusturuluyor...'
    $uygulamaYolu = 'powershell.exe'
    $gorevAdi = 'Spotify kurulum'
    $aksiyon = New-ScheduledTaskAction -Execute $uygulamaYolu -Argument "-NoLogo -NoProfile -Command & `'$spotifyKurulumDosyaYolu`'"
    $tetikleyici = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $ayarlar = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun
    Register-ScheduledTask -Action $aksiyon -Trigger $tetikleyici -TaskName $gorevAdi -Settings $ayarlar -Force | Write-Verbose
    Write-Host 'Kurulum gorevi zamanlandi. Gorev baslatiliyor...'
    Start-ScheduledTask -TaskName $gorevAdi
    Start-Sleep -Seconds 2
    Write-Host 'Gorev kaldiriliyor...'
    Unregister-ScheduledTask -TaskName $gorevAdi -Confirm:$false
    Start-Sleep -Seconds 2
  }
  else
  {
    Start-Process -FilePath "$spotifyKurulumDosyaYolu"
  }

  while ($null -eq (Get-Process -Name Spotify -ErrorAction SilentlyContinue))
  {
    # Kurulum tamamlanana kadar bekliyor
    Start-Sleep -Milliseconds 100
  }

  Write-Host 'Spotify durduruluyor...Yeniden'

  Stop-Process -Name Spotify
  Stop-Process -Name SpotifyWebHelper
  if ([Environment]::Is64BitOperatingSystem) { # Bilgisayarin 64-bit isletim sistemi calistirip calistirmadigini kontrol edin
    Stop-Process -Name SpotifyFullSetupX64
  } else {
     Stop-Process -Name SpotifyFullSetup
  }
}

Write-Host "En son yama (chrome_elf.zip) indiriliyor...`n"
$elfYolu = Join-Path -Path $PWD -ChildPath 'chrome_elf.zip'
try
{
  $baytlar = [System.IO.File]::ReadAllBytes($spotifyCalistirilabilir)
  $peBasligi = [System.BitConverter]::ToUInt16($baytlar[0x3C..0x3D], 0)
  $is64Bit = $baytlar[$peBasligi + 4] -eq 0x64

  if ($is64Bit) {
    $uri = 'https://github.com/mrpond/BlockTheSpot/releases/latest/download/chrome_elf.zip'
  } else {
    Write-Host 'Su anda, x86 mimarisi yeni bir guncelleme almadigi icin reklam engelleyici dogru calismayabilir.'
    $uri = 'https://github.com/mrpond/BlockTheSpot/releases/download/2023.5.20.80/chrome_elf.zip'
  }

  DosyaAl -Uri $uri -HedefDosya "$elfYolu"
}
catch
{
  Write-Output $_
  Start-Sleep
}

Expand-Archive -Force -LiteralPath "$elfYolu" -DestinationPath $PWD
Remove-Item -LiteralPath "$elfYolu" -Force

Write-Host 'Spotify yamaniyor...'
$yamaDosyalari = (Join-Path -Path $PWD -ChildPath 'dpapi.dll'), (Join-Path -Path $PWD -ChildPath 'config.ini')

Copy-Item -LiteralPath $yamaDosyalari -Destination "$spotifyDizini"

function VcRedistKur {
    # https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170
    $vcRedistX86Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
    $vcRedistX64Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

    if ([Environment]::Is64BitOperatingSystem) {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')) {
            $vcRedistX64Dosya = Join-Path -Path $PWD -ChildPath 'vc_redist.x64.exe'
            Write-Host "vc_redist.x64.exe indiriliyor ve kuruluyor..."
            DosyaAl -Uri $vcRedistX64Url -HedefDosya $vcRedistX64Dosya
            Start-Process -FilePath $vcRedistX64Dosya -ArgumentList "/install /quiet /norestart" -Wait
        }
    }
    else {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x86')) {
            $vcRedistX86Dosya = Join-Path -Path $PWD -ChildPath 'vc_redist.x86.exe'
            Write-Host "vc_redist.x86.exe indiriliyor ve kuruluyor..."
            DosyaAl -Uri $vcRedistX86Url -HedefDosya $vcRedistX86Dosya
            Start-Process -FilePath $vcRedistX86Dosya -ArgumentList "/install /quiet /norestart" -Wait
        }
    }
}

VcRedistKur

$tempDizin = $PWD
Pop-Location

Remove-Item -LiteralPath $tempDizin -Recurse

Write-Host 'Yama Islemi Tamamlandi, Spotify baslatiliyor...'

Start-Process -WorkingDirectory $spotifyDizini -FilePath $spotifyCalistirilabilir
Write-Host 'Bitti.'
