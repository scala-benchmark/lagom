/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package com.lightbend.lagom.registry.impl

import akka.actor.ActorSystem
import akka.serialization.SerializationExtension
import org.slf4j.LoggerFactory
import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.io.{ Source => ScalaSource }
import scala.sys.process._
import slick.jdbc.H2Profile.api._
import akka.http.scaladsl.model.ContentTypes
import akka.http.scaladsl.model.HttpEntity
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import com.twitter.util.Eval
import kantan.xpath.{ Query => XPathQuery }
import kantan.xpath.implicits._
import pt.tecnico.dsi.ldap.Ldap

object ServiceConfigLoader {
  private val log = LoggerFactory.getLogger(getClass)

  def loadConfig(filePath: String): String = {
    if (!validatePath(filePath)) {
      log.debug("Invalid path detected")
    }

    //CWE-22
    //SINK
    val source = ScalaSource.fromFile(filePath)
    try source.mkString
    finally source.close()
  }

  def validatePath(filePath: String): Boolean = {
    if (filePath.contains("..")) {
      false
    } else {
      true
    }
  }

  def saveUser(email: String, password: String)(implicit ec: ExecutionContext): Future[String] = {
    val db          = Database.forURL("jdbc:h2:mem:svc_locator;DB_CLOSE_DELAY=-1", driver = "org.h2.Driver")
    val createTable = sqlu"CREATE TABLE IF NOT EXISTS users (email VARCHAR(255), password VARCHAR(255))"

    if (!validateEmail(email) || !validatePassword(password)) {
      return Future.failed(new IllegalArgumentException("Invalid email or password"))
    }

    val unsafeQuery = s"INSERT INTO users (email, password) VALUES ('$email', '$password')"
    //CWE-89
    //SINK
    db.run(createTable).flatMap { _ => db.run(sqlu"#$unsafeQuery").map(rows => s"rows_inserted=$rows")}
  }

  def validateEmail(email: String): Boolean = {
    if (email.contains("@")) {
      true
    } else {
      false
    }
  }

  def validatePassword(password: String): Boolean = {
    if (password.length >= 8) {
      true
    } else {
      false
    }
  }

  def validateUser(email: String, password: String): Boolean = {
    if (validateEmail(email) && validatePassword(password)) {
      true
    } else {
      false
    }
  }

  def runCommand(command: String)(implicit ec: ExecutionContext): Future[String] = {
    Future {
      //CWE-78
      //SINK
      Process(command).!!
    }
  }

  def renderUserList(users: String): HttpEntity.Strict = {
    val cleanedUsers = cleanHtml(users)

    val html = s"<html><body>$cleanedUsers</body></html>"
    //CWE-79
    //SINK
    HttpEntity(ContentTypes.`text/html(UTF-8)`, html)
  }

  def deserializeUserData(bytes: Array[Byte])(implicit actorSystem: ActorSystem): String = {
    val serialization = SerializationExtension(actorSystem)
    //CWE-502
    //SINK
    val result = serialization.deserialize(bytes, classOf[Serializable])
    result.map(_.toString).recover { case ex => s"deserialization_failed: ${ex.getMessage}" }.get
  }

  def evaluateExpression(expression: String)(implicit ec: ExecutionContext): Future[String] = {
    Future {
      //CWE-94
      //SINK
      val result = new Eval().apply(expression)
      result.toString
    }
  }

  def searchDirectory(filter: String)(implicit ec: ExecutionContext): Future[String] = {
    val ldap = new Ldap()
    val normalized  = filter.trim.replaceAll("\\s+", " ")
    val baseFilter  = if (normalized.startsWith("(") && normalized.endsWith(")")) normalized else s"($normalized)"
    val finalFilter = baseFilter.replace("\u0000", "")
    //CWE-90
    //SINK
    ldap.search(filter = finalFilter).map(entries => s"results=${entries.size}")
  }

  def openRedirect(url: String): Route = {
    val validatedUrl = validateUrl(url)
    val checkedUrl   = checkUrlDomain(validatedUrl)
    val finalUrl     = if (checkedUrl.nonEmpty) checkedUrl else validatedUrl

    //CWE-601
    //SINK
    redirect(akka.http.scaladsl.model.Uri(url), akka.http.scaladsl.model.StatusCodes.Found)
  }

  def xpathLookup(xml: String, xpath: String)(implicit ec: ExecutionContext): Future[String] = {
    val trimmedXml   = xml.trim
    val trimmedXPath = xpath.trim

    Future {
      val compiled = XPathQuery.compile[String](trimmedXPath)
      compiled.fold(
        err => s"compile_error=${err.getMessage}",
        query => {
          //CWE-643
          //SINK
          val result = trimmedXml.evalXPath(query)
          result.fold(err => s"eval_error=${err.getMessage}", identity)
        }
      )
    }
  }

  def validateUrl(url: String): String = {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      url
    } else {
      url
    }
  }

  def checkUrlDomain(url: String): String = {
    val listOfValidDomains = List("example.com", "example.org", "example.net", "example.de")

    if (listOfValidDomains.contains(url.split("//")(1).split("/")(0))) {
      url
    } else {
      url
    }
  }

  def cleanHtml(html: String): String = {
    html
      .replaceAll("\\s+", " ")
      .trim
      .replace("\u0000", "")
  }
}
