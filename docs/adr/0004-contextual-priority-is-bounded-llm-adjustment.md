# Contextual Priority is a deterministic base with a bounded LLM adjustment

Contextual Priority is not the language model's score.
A deterministic base score is computed from Severity, EPSS, KEV membership, and fix availability, and the model may adjust it by roughly ±25 on a 0-100 scale while supplying the written rationale.

We rejected letting the model score freely because the queue must be reproducible for the report, must not reshuffle arbitrarily on every re-triage, and because bounding the adjustment makes it possible to render the queue with the adjustment switched off and on.
That toggle is the project's clearest demonstration that the language model is contributing something a severity sort cannot.
The band is wide enough that a KEV-listed critical under an active Exposure Signal reaches the top from any starting position.
