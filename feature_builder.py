import pandas as pd


def build_feature_vector(
    permissions,
    api_calls,
    intent_actions,
    feature_names
):

    features = {
        feature: 0
        for feature in feature_names
    }

    # Permissions

    for permission in permissions:

        short_name = (
            permission
            .split(".")[-1]
        )

        if short_name in features:
            features[short_name] = 1

    # API calls

    for api in api_calls:

        if api in features:
            features[api] = 1

    # Intent Actions
    for action in intent_actions:

        if action in features:
            features[action] = 1

    return pd.DataFrame(
        [features]
    )