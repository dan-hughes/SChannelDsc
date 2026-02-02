Configuration DSC_SChannelProtocolClient_EnableTls12And13
{
    Import-DscResource -ModuleName SChannelDsc

    node $AllNodes.NodeName
    {
        SChannelProtocolClient EnableClient
        {
            IsSingleInstance = 'Yes'
            ProtocolsEnabled = @('Tls12', 'Tls13')
            RebootWhenRequired = $false
        }
    }
}

Configuration DSC_SChannelProtocolClient_DisableTls11
{
    Import-DscResource -ModuleName SChannelDsc

    node $AllNodes.NodeName
    {
        SChannelProtocolClient DisableClient
        {
            IsSingleInstance = 'Yes'
            ProtocolsDisabled = @('Tls11')
            RebootWhenRequired = $false
        }
    }
}

Configuration DSC_SChannelProtocolClient_ResetToDefault
{
    Import-DscResource -ModuleName SChannelDsc

    node $AllNodes.NodeName
    {
        SChannelProtocolClient ResetClient
        {
            IsSingleInstance = 'Yes'
            ProtocolsDefault = @('Tls11', 'Tls12', 'Tls13')
            RebootWhenRequired = $false
        }
    }
}
