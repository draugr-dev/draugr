`make gate` spell-checks files you have added but not yet committed. It read only tracked files, so a new page's first gate never looked at it and the first check that did was CI, after the push.
