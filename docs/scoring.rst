Scoring
=======

Scoring is central to any CTF. CTFd automatically generates a scoreboard that automatically resolves ties and supports score freezing. CTFd supports two models which can alter the score of a user or team.

Solves
------
Solves are what mark a challenge as solved. Solves do not carry a value and defer to the value of their respective Challenge.

Awards
------
Awards have a value defined by their creator (usually an admin). They can be used to give a user/team arbitrary (positive or negative) points.

Tie Breaks
----------
In CTFd, tie breaks are essentially resolved by time. If two teams have the same score, the team with the lower solve ID in the database will be considered on top. For example Team X and Team Y solve the same challenge five minutes apart and both now have 100 points.

Team X will have a Solve ID of 1 for their submission and Team Y will have a Solve ID of 2 for their submission.

Thus Team X will be considered the tie winner.

Formats
-------
