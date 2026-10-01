/* Copyright 2026 Mist Tecnologia LTDA. All rights reserved. */

/* The Forkpoint assertion catalog, kept in the ELF but out of target memory, where the host
 * reads it before a run (see cmake/lwip-forkpoint.cmake). Address 0: ESP-IDF's esptool
 * copies every section with contents and a nonzero address into the app image, loaded or
 * not. */
SECTIONS
{
  .fpt_catalog 0 (INFO) : { KEEP(*(.fpt_catalog)) }
}
