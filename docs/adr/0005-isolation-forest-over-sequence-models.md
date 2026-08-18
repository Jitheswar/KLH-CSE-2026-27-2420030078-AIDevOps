# Isolation Forest over deep sequence models for anomaly detection

Anomaly detection uses an Isolation Forest over windowed multivariate features (CPU, network transmit and receive rates, and the transmit/receive ratio), with a z-score baseline covering cold start until enough windows exist.

Autoencoders and LSTMs were considered and rejected: they need hours of clean multivariate data to outperform a shallow method, this project will have minutes, and the additional effort buys nothing measurable here.
The multivariate feature set is deliberate - a single CPU feature would be caught by a plain threshold, and the forest earns its place only by seeing that CPU rises *together with* a shift in traffic pattern.
