import pickle

# Load the trained model
with open("model.pkl", "rb") as file:
    model = pickle.load(file)

# Get feature importances
feature_importances = model.feature_importances_

# Define your column names here
column_names = ["UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-", 
                "SubDomains", "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL", 
                "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail", 
                "AbnormalURL", "WebsiteForwarding", "StatusBarCust", "DisableRightClick", 
                "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording", "WebsiteTraffic", 
                "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport","class"]

# Create a dictionary mapping feature names to their importances
feature_importance_dict = dict(zip(column_names, feature_importances))

# Sort the dictionary by importances
sorted_features = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)

# Print or visualize the sorted features
print("Features sorted by importance:")
for feature, importance in sorted_features:
    print(f"{feature}: {importance}")
