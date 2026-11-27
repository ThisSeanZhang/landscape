//! Runtime-stage behaviour tests using production skeletons only
//! (`test-support` tier): root -> stage plumbing plus the MSS clamp,
//! fragment caches, and PPPoE raw-socket filter.
mod frag_cache;
mod mss;
mod pppoe;
mod root_stage;
