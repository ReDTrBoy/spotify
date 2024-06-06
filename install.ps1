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

  [System.Security.Principal.WindowsPrincipal] $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent
