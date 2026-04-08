# roomdoo-locks-omnitec

Omnitec / Rent&Pass provider for Roomdoo smart lock integrations.

## Installation

From the root of the monorepo:

    pip install -e "./roomdoo-locks-base"
    pip install -e "./roomdoo-locks-omnitec"

## Usage

    from datetime import datetime, timezone, timedelta
    from roomdoo_locks_omnitec import OmnitecProvider

    provider = OmnitecProvider(
        clientId     = "YOUR_CLIENT_ID",
        clientSecret = "YOUR_CLIENT_SECRET",
        username     = "YOUR_USERNAME",
        password     = "YOUR_PASSWORD"
    )

    starts_at = datetime.now(timezone.utc)
    ends_at   = starts_at + timedelta(hours=1)

    result = provider.create_code("lock-123", starts_at, ends_at)
    print(result.pin)