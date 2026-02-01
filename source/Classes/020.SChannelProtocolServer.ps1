[DscResource()]
class SChannelProtocolServer : SChannelProtocolBase
{
    SChannelProtocolServer () : base ()
    {
    }

    [SChannelProtocolServer] Get()
    {
        # Call the base method to return the properties.
        return ([ResourceBase] $this).Get()
    }

    [void] Set()
    {
        # Call the base method to enforce the properties.
        ([ResourceBase] $this).Set()
    }

    [System.Boolean] Test()
    {
        # Call the base method to test all of the properties that should be enforced.
        return ([ResourceBase] $this).Test()
    }
}
