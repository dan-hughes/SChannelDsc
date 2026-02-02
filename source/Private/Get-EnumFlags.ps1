<#
    .SYNOPSIS
        Expands a [Flags] enum value into its individual flags.

    .DESCRIPTION
        Accepts either an enum value or a numeric value with an explicit
        enum type and returns the individual enum members that are set.

    .PARAMETER Value
        The enum value (or numeric value) to expand. Can be a pipeline input.

    .PARAMETER EnumType
        When passing a numeric value for `Value`, supply the enum `Type`.

    .OUTPUTS
        System.Enum

    .EXAMPLE
        Get-EnumFlags -Value ([SChannelSslProtocols]::Tls12 -bor [SChannelSslProtocols]::Tls13)

    .EXAMPLE
        # When you have an integer and know the enum type
        Get-EnumFlags -Value 48 -EnumType ([type] 'SChannelSslProtocols')
#>
function Get-EnumFlags
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.Enum]
        $Value
    )

    process
    {
        $enumType = $Value.GetType()

        foreach ($flag in [Enum]::GetValues($enumType))
        {
            if ([int]$flag -ne 0 -and $Value.HasFlag($flag))
            {
                $flag
            }
        }
    }
}
