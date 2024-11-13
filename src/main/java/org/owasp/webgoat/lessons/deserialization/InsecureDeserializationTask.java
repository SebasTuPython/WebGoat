/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */
package org.owasp.webgoat.lessons.deserialization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask extends AssignmentEndpoint {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @PostMapping("/InsecureDeserialization/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String token) {
    long before;
    long after;
    int delay;

    try {
      String jsonString = new String(Base64.getDecoder().decode(token));
      JsonNode jsonNode = objectMapper.readTree(jsonString);

      if (!jsonNode.has("taskId") || !jsonNode.has("taskData")) {
        return failed(this).feedback("insecure-deserialization.invaliddata").build();
      }

      before = System.currentTimeMillis();

      String taskId = jsonNode.get("taskId").asText();
      String taskData = jsonNode.get("taskData").asText();

      if (!isValidTask(taskId, taskData)) {
        return failed(this).feedback("insecure-deserialization.invaliddata").build();
      }

      after = System.currentTimeMillis();

    } catch (IOException e) {
      return failed(this).feedback("insecure-deserialization.invalidformat").build();
    }

    delay = (int) (after - before);
    if (delay > 7000 || delay < 3000) {
      return failed(this).build();
    }
    return success(this).build();
  }

  private boolean isValidTask(String taskId, String taskData) {
    return true;
  }
}
