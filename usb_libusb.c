/*
 * avrdude - A Downloader/Uploader for AVR device programmers
 * Copyright (C) 2005,2006 Joerg Wunsch
 * Copyright (C) 2006 David Moore
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* $Id$ */

/*
 * USB interface via libusb for avrdude.
 */

#include "ac_cfg.h"
#if defined(HAVE_LIBUSB)


#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>

#include <libusb-1.0/libusb.h>
#include "avrdude.h"
#include "libavrdude.h"

#include "usbdevs.h"

#if defined(WIN32NATIVE)
/* someone has defined "interface" to "struct" in Cygwin */
#  undef interface
#endif

static char usbbuf[USBDEV_MAX_XFER_3];
static int buflen = -1, bufptr;

static int usb_interface;

/*
 * The "baud" parameter is meaningless for USB devices, so we reuse it
 * to pass the desired USB device ID.
 */
static int usbdev_open(char * port, union pinfo pinfo, union filedescriptor *fd) {
    char string[256];
    char product[256];
    char *serno, *cp2;
    int i;
    int iface;
    size_t x;
    libusb_context *context = NULL;
    libusb_device **usb_dev_list = NULL;
    int rc = 0;
    ssize_t count = 0;

    /*
    * The syntax for usb devices is defined as:
    *
    * -P usb[:serialnumber]
    *
    * See if we've got a serial number passed here.  The serial number
    * might contain colons which we remove below, and we compare it
    * right-to-left, so only the least significant nibbles need to be
    * specified.
    */
    if ((serno = strchr(port, ':')) != NULL) {
        /* first, drop all colons there if any */
        cp2 = ++serno;
        while ((cp2 = strchr(cp2, ':')) != NULL) {
            x = strlen(cp2) - 1;
            memmove(cp2, cp2 + 1, x);
            cp2[x] = '\0';
        }
        if (strlen(serno) > 12) {
            avrdude_message(MSG_INFO, "%s: usbdev_open(): invalid serial number \"%s\"\n", progname, serno);
            return -1;
        }
    }

    if (fd->usb.max_xfer == 0) { fd->usb.max_xfer = USBDEV_MAX_XFER_MKII; }

    rc = libusb_init(&context);
    assert(rc == 0);
    count = libusb_get_device_list(context, &usb_dev_list);
    assert(count > 0);

    for (size_t idx = 0; idx < count; ++idx) {
        libusb_device *device = usb_dev_list[idx];
        struct libusb_device_descriptor desc;
        libusb_device_handle *udev;

        rc = libusb_get_device_descriptor(device, &desc);
        assert(rc == 0);

        avrdude_message(MSG_INFO, "Usb device %04x, %04x \n", desc.idVendor, desc.idProduct);
        if (desc.idVendor == pinfo.usbinfo.vid && desc.idProduct == pinfo.usbinfo.pid) {
            avrdude_message(MSG_INFO, "Possible dev, try open \n");
            rc = libusb_open(device, &udev);
            if (rc == 0) {
                /* yeah, we found something */
                rc = libusb_get_string_descriptor_ascii(udev, desc.iSerialNumber, string, sizeof(string));
                if (rc < 0) {
                    avrdude_message(MSG_INFO, "%s: usb_open(): cannot read serial number \"%s\"\n",
                                    progname, libusb_strerror(rc));
                    /*
                     * On some systems, libusb appears to have
                     * problems sending control messages.  Catch the
                     * benign case where the user did not request a
                     * particular serial number, so we could
                     * continue anyway.
                     */
                    if (serno != NULL)
                      return -1; /* no chance */
                    else
                      strcpy(string, "[unknown]");
                  }

                rc = libusb_get_string_descriptor_ascii(udev, desc.iProduct, product, sizeof(product));
                if (rc < 0) {
                    avrdude_message(MSG_INFO, "%s: usb_open(): cannot read product name \"%s\"\n",
                                    progname, libusb_strerror(rc));
                    strcpy(product, "[unnamed product]");
                  }
                /*
                 * The CMSIS-DAP specification mandates the string
                 * "CMSIS-DAP" must be present somewhere in the
                 * product name string for a device compliant to
                 * that protocol.  Use this for the decisision
                 * whether we have to search for a HID interface
                 * below.
                 */
                if(strstr(product, "CMSIS-DAP") != NULL)
                {
                    pinfo.usbinfo.flags |= PINFO_FL_USEHID;
                    /* The JTAGICE3 running the CMSIS-DAP firmware doesn't
                     * use a separate endpoint for event reception. */
                    fd->usb.eep = 0;
                }

                if(strstr(product, "mEDBG") != NULL)
                {
                    /* The AVR Xplained Mini uses different endpoints. */
                    fd->usb.rep = 0x81;
                    fd->usb.wep = 0x02;
                }

                avrdude_message(MSG_NOTICE, "%s: usbdev_open(): Found %s, serno: %s\n",
                                  progname, product, string);
                if (serno != NULL)
                  {
                    /*
                     * See if the serial number requested by the
                     * user matches what we found, matching
                     * right-to-left.
                     */
                    x = strlen(string) - strlen(serno);
                    if (strcasecmp(string + x, serno) != 0)
                      {
                        avrdude_message(MSG_DEBUG, "%s: usbdev_open(): serial number doesn't match\n",
                                          progname);
                        libusb_close(udev);
                            continue;
                      }
                  }

                struct libusb_config_descriptor *conf_desc;
                rc = libusb_get_config_descriptor(device, 0, &conf_desc);
                if (rc != 0)
                  {
                    avrdude_message(MSG_INFO, "%s: usbdev_open(): USB device has no configuration, err: \"%s\"\n",
                                    progname, libusb_strerror(rc));
                    goto trynext;
                  }
                rc = libusb_set_configuration(udev, conf_desc->bConfigurationValue);
                if (rc != 0)
                  {
                    avrdude_message(MSG_INFO, "%s: usbdev_open(): WARNING: failed to set configuration %d: %s\n",
                                    progname, conf_desc->bConfigurationValue,
                                    libusb_strerror(rc));
                    /* let's hope it has already been configured */
                    /* goto trynext; */
                  }

                for (iface = 0; iface < conf_desc->bNumInterfaces; iface++) {
                    usb_interface = conf_desc->interface[iface].altsetting[0].bInterfaceNumber;
#ifdef LIBUSB_HAS_GET_DRIVER_NP
                    /*
                     * Many Linux systems attach the usbhid driver
                     * by default to any HID-class device.  On
                     * those, the driver needs to be detached before
                     * we can claim the interface.
                     */
                    (void)libusb_detach_kernel_driver(udev, usb_interface);
#endif
                    rc = libusb_claim_interface(udev, usb_interface);
                    if (rc != 0)
                      {
                        avrdude_message(MSG_INFO, "%s: usbdev_open(): error claiming interface %d: %s\n",
                                        progname, usb_interface, libusb_strerror(rc));
                      }
                    else
                      {
                        if (pinfo.usbinfo.flags & PINFO_FL_USEHID)
                          {
                            /* only consider an interface that is of class HID */
                            if (conf_desc->interface[iface].altsetting[0].bInterfaceClass != LIBUSB_CLASS_HID) {
                                continue;
                            }
                            fd->usb.use_interrupt_xfer = 1;
                          }
                        break;
                      }
                  }

                if (iface == conf_desc->bNumInterfaces)
                  {
                    avrdude_message(MSG_INFO, "%s: usbdev_open(): no usable interface found\n",
                                    progname);
                    goto trynext;
                  }

                fd->usb.handle = udev;
                if (fd->usb.rep == 0)
                  {
                    /* Try finding out what our read endpoint is. */
                    for (i = 0; i < conf_desc->interface[iface].altsetting[0].bNumEndpoints; i++)
                      {
                        int possible_ep = conf_desc->interface[iface].altsetting[0].
                        endpoint[i].bEndpointAddress;

                        if ((possible_ep & LIBUSB_ENDPOINT_DIR_MASK) != 0)
                          {
                            avrdude_message(MSG_NOTICE2, "%s: usbdev_open(): using read endpoint 0x%02x\n",
                                                progname, possible_ep);
                            fd->usb.rep = possible_ep;
                            break;
                          }
                      }
                    if (fd->usb.rep == 0)
                      {
                        avrdude_message(MSG_INFO, "%s: usbdev_open(): cannot find a read endpoint, using 0x%02x\n",
                                        progname, USBDEV_BULK_EP_READ_MKII);
                        fd->usb.rep = USBDEV_BULK_EP_READ_MKII;
                      }
                  }
                for (i = 0; i < conf_desc->interface[iface].altsetting[0].bNumEndpoints; i++)
                  {
                    if ((conf_desc->interface[iface].altsetting[0].endpoint[i].bEndpointAddress == fd->usb.rep ||
                         conf_desc->interface[iface].altsetting[0].endpoint[i].bEndpointAddress == fd->usb.wep) &&
                        conf_desc->interface[iface].altsetting[0].endpoint[i].wMaxPacketSize < fd->usb.max_xfer)
                      {
                        avrdude_message(MSG_NOTICE, "%s: max packet size expected %d, but found %d due to EP 0x%02x's wMaxPacketSize\n",
                                          progname,
                                          fd->usb.max_xfer,
                                          conf_desc->interface[iface].altsetting[0].endpoint[i].wMaxPacketSize,
                                          conf_desc->interface[iface].altsetting[0].endpoint[i].bEndpointAddress);
                        fd->usb.max_xfer = conf_desc->interface[iface].altsetting[0].endpoint[i].wMaxPacketSize;
                      }
                  }
                if (pinfo.usbinfo.flags & PINFO_FL_USEHID)
                  {
                    rc = libusb_control_transfer(udev, 0x21, 0x0a /* SET_IDLE */, 0, 0, NULL, 0, 100);
                    if (rc != 0)
                      avrdude_message(MSG_INFO, "%s: usbdev_open(): SET_IDLE failed, err: \"%s\"\n", progname,
                              libusb_strerror(rc));
                  }
                return 0;
                trynext:
                libusb_close(udev);
            } else {
                avrdude_message(MSG_INFO, "%s: usbdev_open(): cannot open device: %s\n", progname, libusb_strerror(rc));
            }
        }
    }

    if ((pinfo.usbinfo.flags & PINFO_FL_SILENT) == 0) {
      avrdude_message(MSG_NOTICE, "%s: usbdev_open(): did not find any%s USB device \"%s\" (0x%04x:0x%04x)\n",
              progname, serno? " (matching)": "", port,
              (unsigned)pinfo.usbinfo.vid, (unsigned)pinfo.usbinfo.pid
      );
    }
    return -1;
}

static void usbdev_close(union filedescriptor *fd)
{
  libusb_device_handle *udev = (libusb_device_handle *)fd->usb.handle;

  if (udev == NULL)
    return;

  (void)libusb_release_interface(udev, usb_interface);

#if defined(__linux__)
  /*
   * Without this reset, the AVRISP mkII seems to stall the second
   * time we try to connect to it.  This is not necessary on
   * FreeBSD.
   */
  libusb_reset_device(udev);
#endif

  libusb_close(udev);
}


static int usbdev_send(union filedescriptor *fd, const unsigned char *bp, size_t mlen)
{
  libusb_device_handle *udev = (libusb_device_handle *)fd->usb.handle;
  int err;
  int i = mlen;
  const unsigned char * p = bp;
  int tx_size;
  int actual_length;

  if (udev == NULL)
    return -1;

  /*
   * Split the frame into multiple packets.  It's important to make
   * sure we finish with a short packet, or else the device won't know
   * the frame is finished.  For example, if we need to send 64 bytes,
   * we must send a packet of length 64 followed by a packet of length
   * 0.
   */
  do {
    tx_size = (mlen < fd->usb.max_xfer)? mlen: fd->usb.max_xfer;
    if (fd->usb.use_interrupt_xfer)
      err = libusb_interrupt_transfer(udev, fd->usb.wep, (char *)bp, tx_size, &actual_length, 10000);
    else
      err = libusb_bulk_transfer(udev, fd->usb.wep, (char *)bp, tx_size, &actual_length, 10000);
    if (err != 0 || actual_length != tx_size)
    {
        avrdude_message(MSG_INFO, "%s: usbdev_send(): wrote %d out of %d bytes, err = %s\n",
                progname, actual_length, tx_size, libusb_strerror(err));
        return -1;
    }
    bp += tx_size;
    mlen -= tx_size;
  } while (mlen > 0);

  if (verbose > 3)
  {
      avrdude_message(MSG_TRACE, "%s: Sent: ", progname);

      while (i) {
        unsigned char c = *p;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE, ". ");
        }
        avrdude_message(MSG_TRACE, "[%02x] ", c);

        p++;
        i--;
      }
      avrdude_message(MSG_TRACE, "\n");
  }
  return 0;
}

/*
 * As calls to usb_bulk_read() result in exactly one USB request, we
 * have to buffer the read results ourselves, so the single-char read
 * requests performed by the upper layers will be handled.  In order
 * to do this, we maintain a private buffer of what we've got so far,
 * and transparently issue another USB read request if the buffer is
 * empty and more data are requested.
 */
static int
usb_fill_buf(libusb_device_handle *udev, int maxsize, int ep, int use_interrupt_xfer)
{
  int err;
  int actual_length;

  if (use_interrupt_xfer)
    err = libusb_interrupt_transfer(udev, ep, usbbuf, maxsize, &actual_length, 10000);
  else
    err = libusb_bulk_transfer(udev, ep, usbbuf, maxsize, &actual_length, 10000);
  if (err != 0 || actual_length < 0)
    {
      avrdude_message(MSG_NOTICE2, "%s: usb_fill_buf(): usb_%s_read() error %s\n",
		progname, (use_interrupt_xfer? "interrupt": "bulk"),
		libusb_strerror(err));
      return -1;
    }

  buflen = actual_length;
  bufptr = 0;

  return 0;
}

static int usbdev_recv(union filedescriptor *fd, unsigned char *buf, size_t nbytes)
{
  libusb_device_handle *udev = (libusb_device_handle *)fd->usb.handle;
  int i, amnt;
  unsigned char * p = buf;

  if (udev == NULL)
    return -1;

  for (i = 0; nbytes > 0;)
    {
      if (buflen <= bufptr)
	{
	  if (usb_fill_buf(udev, fd->usb.max_xfer, fd->usb.rep, fd->usb.use_interrupt_xfer) < 0)
	    return -1;
	}
      amnt = buflen - bufptr > nbytes? nbytes: buflen - bufptr;
      memcpy(buf + i, usbbuf + bufptr, amnt);
      bufptr += amnt;
      nbytes -= amnt;
      i += amnt;
    }

  if (verbose > 4)
  {
      avrdude_message(MSG_TRACE2, "%s: Recv: ", progname);

      while (i) {
        unsigned char c = *p;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE2, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE2, ". ");
        }
        avrdude_message(MSG_TRACE2, "[%02x] ", c);

        p++;
        i--;
      }
      avrdude_message(MSG_TRACE2, "\n");
  }

  return 0;
}

/*
 * This version of recv keeps reading packets until we receive a short
 * packet.  Then, the entire frame is assembled and returned to the
 * user.  The length will be unknown in advance, so we return the
 * length as the return value of this function, or -1 in case of an
 * error.
 *
 * This is used for the AVRISP mkII device.
 */
static int usbdev_recv_frame(union filedescriptor *fd, unsigned char *buf, size_t nbytes)
{
  libusb_device_handle *udev = (libusb_device_handle *)fd->usb.handle;
  int err, n;
  int i;
  int actual_length;
  unsigned char * p = buf;

  if (udev == NULL)
    return -1;

  /* If there's an event EP, and it has data pending, return it first. */
  if (fd->usb.eep != 0)
  {
      err = libusb_bulk_transfer(udev, fd->usb.eep, usbbuf, fd->usb.max_xfer, &actual_length, 1);
      if (actual_length > 4)
      {
          memcpy(buf, usbbuf, actual_length);
          n = actual_length;
          n |= USB_RECV_FLAG_EVENT;
          goto printout;
      }
      else if (err != 0 || actual_length > 0)
      {
	  avrdude_message(MSG_INFO, "Short event err = %d len = %d, ignored.\n", err, actual_length);
	  /* fallthrough */
      }
  }

  n = 0;
  do
    {
      if (fd->usb.use_interrupt_xfer)
	err = libusb_interrupt_transfer(udev, fd->usb.rep, usbbuf, fd->usb.max_xfer, &actual_length, 10000);
      else
	err = libusb_bulk_transfer(udev, fd->usb.rep, usbbuf, fd->usb.max_xfer, &actual_length, 10000);
      if (err != 0 || actual_length < 0)
	{
          avrdude_message(MSG_NOTICE2, "%s: usbdev_recv_frame(): usb_%s_read(): %s\n",
		    progname, (fd->usb.use_interrupt_xfer? "interrupt": "bulk"),
		    libusb_strerror(err));
	  return -1;
	}

      if (err != 0 || actual_length <= nbytes)
	{
	  memcpy (buf, usbbuf, actual_length);
	  buf += actual_length;
	}
      else
        {
            return -1; // buffer overflow
        }

      n += actual_length;
      nbytes -= actual_length;
    }
  while (nbytes > 0 && actual_length == fd->usb.max_xfer);

/*
 this ends when the buffer is completly filled (nbytes=0) or was too small (nbytes< 0)
 or a short packet is found.
 however we cannot say for nbytes=0 that there was really a packet completed,
 we had to check the last rv value than for a short packet,
 but what happens if the packet does not end with a short packet?
 and what if the buffer is filled without the packet was completed?

 preconditions:
    expected packet is not a multiple of usb.max_xfer. (prevents further waiting)

    expected packet is shorter than the provided buffer (so it cannot filled completely)
    or buffer size is not a multiple of usb.max_xfer. (so it can clearly detected if the buffer was overflown.)
*/

  printout:
  if (verbose > 3)
  {
      i = n & USB_RECV_LENGTH_MASK;
      avrdude_message(MSG_TRACE, "%s: Recv: ", progname);

      while (i) {
        unsigned char c = *p;
        if (isprint(c)) {
          avrdude_message(MSG_TRACE, "%c ", c);
        }
        else {
          avrdude_message(MSG_TRACE, ". ");
        }
        avrdude_message(MSG_TRACE, "[%02x] ", c);

        p++;
        i--;
      }
      avrdude_message(MSG_TRACE, "\n");
  }
  return n;
}

static int usbdev_drain(union filedescriptor *fd, int display)
{
  /*
   * There is not much point in trying to flush any data
   * on an USB endpoint, as the endpoint is supposed to
   * start afresh after being configured from the host.
   *
   * As trying to flush the data here caused strange effects
   * in some situations (see
   * https://savannah.nongnu.org/bugs/index.php?43268 )
   * better avoid it.
   */

  return 0;
}

/*
 * Device descriptor for the JTAG ICE mkII.
 */
struct serial_device usb_serdev =
{
  .open = usbdev_open,
  .close = usbdev_close,
  .send = usbdev_send,
  .recv = usbdev_recv,
  .drain = usbdev_drain,
  .flags = SERDEV_FL_NONE,
};

/*
 * Device descriptor for the AVRISP mkII.
 */
struct serial_device usb_serdev_frame =
{
  .open = usbdev_open,
  .close = usbdev_close,
  .send = usbdev_send,
  .recv = usbdev_recv_frame,
  .drain = usbdev_drain,
  .flags = SERDEV_FL_NONE,
};

#endif  /* HAVE_LIBUSB */
