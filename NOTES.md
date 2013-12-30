* Allocating C-structures in Go memory is fine as long as the garbage collector is either non-moving or at least stop-the-world type. Both of these conditions hold as of Go 1.2. As soon as Go objects start moving around while the C-call is in progress, the allocation strategy will have to be completely rethought. At this point it seems we'll be fine for foreseable future though.