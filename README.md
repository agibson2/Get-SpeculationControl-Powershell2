# Get-SpeculationControl-Powershell2

This is a modification to allow Get-SpeculationControlSettings to work on powershell 2.0.  I did minor changes to fix parameters
needing =$true, Adding bit shifting functions from another source, and an alternative Get-CimInstance called Get-MyCimInstance
also pulled from another source.

Microsoft really should modify the original to support powershell 2.0 so that additional software (newer powershell) doesn't
need to be installedon Windows 2008 R2.

See the original source download link below:
https://gallery.technet.microsoft.com/scriptcenter/Speculation-Control-e36f0050#content

The other sources for functions were pulled from...
https://powershell.org/2013/04/get-ciminstance-from-powershell-2-0/
https://stackoverflow.com/questions/35116636/bit-shifting-in-powershell-2-0
