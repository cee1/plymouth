/* vim: ts=4 sw=2 expandtab autoindent cindent
 * ply-image.c - png file loader
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 * Copyright (C) 2003 University of Southern California
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Some implementation taken from the cairo library.
 *
 * Written by: Kristian Høgsberg <krh@redhat.com>
 *             Ray Strode <rstrode@redhat.com>
 *             Carl D. Worth (cworth@cworth.org>
 */
#include "config.h"
#include "ply-image.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <png.h>

#include <linux/fb.h>

#include "ply-utils.h"

typedef union
{
 uint32_t *as_pixels;
 png_byte *as_png_bytes;
 char *address;
} PlyImageLayout;

struct _PlyImage
{
  char  *filename;
  FILE  *fp;

  PlyImageLayout layout;
  size_t size;

  long width;
  long height;
};

static bool ply_image_open_file (PlyImage *image);
static void ply_image_close_file (PlyImage *image);

static bool
ply_image_open_file (PlyImage *image)
{
  assert (image != NULL);

  image->fp = fopen (image->filename, "r");

  if (image->fp == NULL)
    return false;
  return true;
}

static void
ply_image_close_file (PlyImage *image)
{
  assert (image != NULL);

  if (image->fp == NULL)
    return;
  fclose (image->fp);
  image->fp = NULL;
}

PlyImage *
ply_image_new (const char *filename)
{
  PlyImage *image;

  assert (filename != NULL);

  image = calloc (1, sizeof (PlyImage));

  image->filename = strdup (filename);
  image->fp = NULL;
  image->layout.address = NULL;
  image->size = -1;
  image->width = -1;
  image->height = -1;

  return image;
}

void
ply_image_free (PlyImage *image)
{
  assert (image != NULL);
  assert (image->filename != NULL);

  if (image->layout.address != NULL)
    {
      free (image->layout.address);
      image->layout.address = NULL;
    }

  free (image->filename);
  free (image);
}

static void
transform_to_argb32 (png_struct   *png,
                     png_row_info *row_info,
                     png_byte     *data)
{
  unsigned int i;

  for (i = 0; i < row_info->rowbytes; i += 4) 
  {
    uint8_t  red, green, blue, alpha;
    uint32_t pixel_value;

    red = data[i + 0];
    green = data[i + 1];
    blue = data[i + 2];
    alpha = data[i + 3];

    red = (uint8_t) CLAMP (((red / 255.0) * (alpha / 255.0)) * 255.0, 0, 255.0);
    green = (uint8_t) CLAMP (((green / 255.0) * (alpha / 255.0)) * 255.0,
                             0, 255.0);
    blue = (uint8_t) CLAMP (((blue / 255.0) * (alpha / 255.0)) * 255.0, 0, 255.0);

    pixel_value = (alpha << 24) | (red << 16) | (green << 8) | (blue << 0);
    memcpy (data + i, &pixel_value, sizeof (uint32_t));
  }
}

bool
ply_image_load (PlyImage *image)
{
  png_struct *png;
  png_info *info;
  png_uint_32 width, height, bytes_per_row, row;
  int bits_per_pixel, color_type, interlace_method;
  png_byte **rows;

  assert (image != NULL);

  if (!ply_image_open_file (image))
    return false;

  png = png_create_read_struct (PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  assert (png != NULL);

  info = png_create_info_struct (png);
  assert (info != NULL);

  png_init_io (png, image->fp);

  if (setjmp (png_jmpbuf (png)) != 0)
    {
      ply_image_close_file (image);
      return false;
    }

  png_read_info (png, info);
  png_get_IHDR (png, info,
                &width, &height, &bits_per_pixel,
                &color_type, &interlace_method, NULL, NULL);
  bytes_per_row = 4 * width;

  if (color_type == PNG_COLOR_TYPE_PALETTE)
    png_set_palette_to_rgb (png);

  if ((color_type == PNG_COLOR_TYPE_GRAY) && (bits_per_pixel < 8))
    png_set_gray_1_2_4_to_8 (png);

  if (png_get_valid (png, info, PNG_INFO_tRNS))
    png_set_tRNS_to_alpha (png);

  if (bits_per_pixel == 16)
    png_set_strip_16 (png);

  if (bits_per_pixel < 8)
    png_set_packing (png);

  if ((color_type == PNG_COLOR_TYPE_GRAY)
      || (color_type == PNG_COLOR_TYPE_GRAY_ALPHA))
    png_set_gray_to_rgb (png);

  if (interlace_method != PNG_INTERLACE_NONE)
    png_set_interlace_handling (png);

  png_set_filler (png, 0xff, PNG_FILLER_AFTER);

  png_set_read_user_transform_fn (png, transform_to_argb32);

  png_read_update_info (png, info);

  rows = malloc (height * sizeof (png_byte *));
  image->layout.address = malloc (height * bytes_per_row);

  for (row = 0; row < height; row++)
    rows[row] = &image->layout.as_png_bytes[row * bytes_per_row];

  png_read_image (png, rows);

  free (rows);
  png_read_end (png, info);
  ply_image_close_file (image);

  image->width = width;
  image->height = height;

  return true;
}

uint32_t *
ply_image_get_data (PlyImage *image)
{
  assert (image != NULL);

  return image->layout.as_pixels;
}

ssize_t
ply_image_get_size (PlyImage *image)
{
  assert (image != NULL);

  return image->size;
}

long
ply_image_get_width (PlyImage *image)
{
  assert (image != NULL);

  return image->width;
}

long
ply_image_get_height (PlyImage *image)
{
  assert (image != NULL);

  return image->height;
}

#ifdef PLY_IMAGE_ENABLE_TEST

#include "ply-video-buffer.h"

#include <math.h>
#include <stdio.h>
#include <sys/time.h>

#ifndef FRAMES_PER_SECOND
#define FRAMES_PER_SECOND 30
#endif

static double
get_current_time (void)
{
  const double microseconds_per_second = 1000000.0;
  double timestamp;
  struct timeval now = { 0L, /* zero-filled */ };

  gettimeofday (&now, NULL);
  timestamp = ((microseconds_per_second * now.tv_sec) + now.tv_usec) /
               microseconds_per_second;

  return timestamp;
}

static void
animate_at_time (PlyVideoBuffer *buffer,
                 PlyImage       *image,
                 double          time)
{
  PlyVideoBufferArea area;
  uint32_t *data;
  long width, height;
  double opacity = 0.0;

  data = ply_image_get_data (image);
  width = ply_image_get_width (image);
  height = ply_image_get_height (image);

  ply_video_buffer_get_size (buffer, &area);
  area.x = (area.width / 2) - (width / 2);
  area.y = (area.height / 2) - (height / 2);
  area.width = width;
  area.height = height;

  opacity = .5 * sin (time * (2 * M_PI)) + .5;
  ply_video_buffer_pause_updates (buffer);
  ply_video_buffer_fill_with_color (buffer, &area,
                                    60.0/256.0, 110.0/256.0, 180.0/256.0, 1.0);
  ply_video_buffer_fill_with_argb32_data_at_opacity (buffer, &area, 
                                                     0, 0, width, height, 
                                                     data, 0.3);
  ply_video_buffer_unpause_updates (buffer);
}

int
main (int    argc,
      char **argv)
{
  PlyImage *image;
  PlyVideoBuffer *buffer;
  int exit_code;
  double start_time;

  exit_code = 0;

  image = ply_image_new ("booting.png");

  if (!ply_image_load (image))
    {
      exit_code = errno;
      perror ("could not load image");
      return exit_code;
    }

  buffer = ply_video_buffer_new (NULL);

  if (!ply_video_buffer_open (buffer))
    {
      exit_code = errno;
      perror ("could not open framebuffer");
      return exit_code;
    }

  start_time = get_current_time ();
  ply_video_buffer_fill_with_color (buffer, NULL,
                                    60.0/256.0, 110.0/256.0, 180.0/256.0, 1.0);
  while ("we want to see ad-hoc animations")
    {
      animate_at_time (buffer, image, get_current_time () - start_time);
      usleep ((long) (1000000 / FRAMES_PER_SECOND));
    }
  ply_video_buffer_close (buffer);
  ply_video_buffer_free (buffer);

  ply_image_free (image);

  return exit_code;
}

#endif /* PLY_IMAGE_ENABLE_TEST */
